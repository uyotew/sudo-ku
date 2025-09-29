const std = @import("std");
const mem = std.mem;
const linux = std.os.linux;
const posix = std.posix;
const fatal = std.process.fatal;
const playSudoku = @import("sudoku.zig").playSudoku;
const authenticate = @import("auth.zig").authenticate;

var read_buffer: [4096]u8 = undefined;
var write_buffer: [4096]u8 = undefined;

const persist_dir = "/tmp/sudo-ku";

fn usage(progname: []const u8) noreturn {
    std.log.info(
        \\usage: {s} [options] [--] command
        \\options:
        \\ -h --help
        \\ -u --user username
        \\      run command as user (default root)
        \\ -c --check sudo-kuers
        \\      check/verify syntax of sudo-kuers file
        \\ -l   reset all persistent sessions
        \\
    , .{progname});
    std.process.exit(0);
}

pub fn main() !void {
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try std.process.argsAlloc(arena);
    const progname = args[0];

    var as_user: []const u8 = "root";

    var arg_idx: usize = 1;
    while (arg_idx < args.len) : (arg_idx += 1) {
        const arg = args[arg_idx];
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            usage(progname);
        } else if (mem.eql(u8, arg, "-u") or mem.eql(u8, arg, "--user")) {
            arg_idx += 1;
            if (arg_idx >= args.len) fatal("{s} expects a username", .{arg});
            as_user = args[arg_idx];
        } else if (mem.eql(u8, arg, "-c") or mem.eql(u8, arg, "--check")) {
            arg_idx += 1;
            if (arg_idx >= args.len) fatal("{s} expects a file path", .{arg});
            // set the effective id to the real id, so
            // --check cannot be used too snoop on unowned files
            try posix.seteuid(posix.getuid());
            const path = args[arg_idx];
            const file = std.fs.cwd().openFile(path, .{}) catch |err| fatal("{s}: {t}", .{ path, err });
            defer file.close();
            var file_reader = file.reader(&read_buffer);
            var found_error = false;
            var rit: RulesIterator = .{ .reader = &file_reader.interface };
            while (try rit.next()) |rule_or_err| switch (rule_or_err) {
                .err_msg => |msg| {
                    found_error = true;
                    std.log.err("{s}:line {}: {s}", .{ path, rit.line_n, msg });
                },
                .rule => |_| {},
            };
            if (found_error) std.process.exit(1) else std.process.exit(0);
        } else if (mem.eql(u8, arg, "-l")) {
            std.fs.cwd().deleteTree(persist_dir) catch |err| fatal("{s}: {t}", .{ persist_dir, err });
            std.process.exit(0);
        } else if (mem.eql(u8, arg, "--")) {
            arg_idx += 1;
            break;
        } else break;
    }
    if (arg_idx >= args.len) fatal("expected command", .{});
    const argv = args[arg_idx..];
    const command = argv[0];

    const caller: Caller = try .stat(arena);
    const etc: Etc = try .parse(arena);

    const PATH = caller.env.get("PATH") orelse fatal("no PATH", .{});
    var path_it = mem.tokenizeScalar(u8, PATH, ':');
    const absolute_command = while (path_it.next()) |path| {
        const absolute_path = try std.fs.path.join(arena, &.{ path, command });
        std.fs.accessAbsolute(absolute_path, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            error.AccessDenied => {},
            else => fatal("{s}: {t}", .{ absolute_path, err }),
        };
        break absolute_path;
    } else std.fs.cwd().realpathAlloc(arena, command) catch |err|
        fatal("{s}: {t}", .{ command, err });

    const sudokuers_path = "/etc/sudo-kuers";
    const file = std.fs.cwd().openFile(sudokuers_path, .{}) catch |err|
        fatal("{s}: {t}", .{ sudokuers_path, err });
    defer file.close();

    if (posix.fstat(file.handle)) |stat| {
        if (stat.uid != posix.geteuid()) fatal("owner of {s} is not the effective user", .{sudokuers_path});
        if (stat.mode & 0o022 != 0) fatal("only the owner can have write access to {s}", .{sudokuers_path});
    } else |err| fatal("{s} fstat error: {t}", .{ sudokuers_path, err });

    var rule_buf: [4096]u8 = undefined;
    var file_reader = file.reader(&rule_buf);

    var rit: RulesIterator = .{ .reader = &file_reader.interface };
    const rule = outer: while (try rit.next()) |rule_or_err| {
        const rule = switch (rule_or_err) {
            .err_msg => |_| fatal("{s} parse error, use --check for details", .{sudokuers_path}),
            .rule => |r| r,
        };
        const id_match = switch (rule.identity) {
            .user => |u| if (etc.users.get(u)) |user| user.uid == caller.uid else false,
            .group => |g| if (etc.groups.get(g)) |gid| caller.groups.contains(gid) else false,
        };
        if (!id_match) continue;
        if (rule.as_user) |rau| if (!mem.eql(u8, rau, as_user)) continue;
        if (rule.cmd) |rc| if (!mem.eql(u8, rc, absolute_command)) continue;
        if (rule.args_str) |ra| {
            var sit = mem.tokenizeAny(u8, ra, " \t");
            var argv_i: usize = 1;
            if (sit.peek() == null and argv.len > 1) continue;
            while (sit.next()) |arg| : (argv_i += 1) {
                if (argv_i > argv.len) continue :outer;
                if (!mem.eql(u8, arg, argv[argv_i])) continue :outer;
            }
        }
        break rule;
    } else fatal("no matching rules", .{});

    switch (rule.access) {
        .permit => {},
        .deny => fatal("denied", .{}),
    }

    var skip_auth = false;
    var persist_path: ?[]const u8 = null;

    if (rule.options.persist) |mins| blk: {
        std.fs.makeDirAbsolute(persist_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => fatal("{s}: {t}", .{ persist_dir, err }),
        };
        const hash_raw = std.hash.Wyhash.hash(0, rule.line);
        const encoder = std.base64.url_safe.Encoder;
        var hash_buf: [encoder.calcSize(8)]u8 = undefined;
        const hash = encoder.encode(&hash_buf, &@as([8]u8, @bitCast(hash_raw)));
        persist_path = try std.fs.path.join(arena, &.{ persist_dir, hash });

        const persist_file = std.fs.openFileAbsolute(persist_path.?, .{ .mode = .write_only }) catch |err| switch (err) {
            error.FileNotFound => break :blk,
            else => fatal("{s}: {t}", .{ persist_path.?, err }),
        };
        defer persist_file.close();

        const stat = try persist_file.stat();
        const mins_in_ns: i128 = @as(i128, @intCast(mins)) * std.time.ns_per_min;
        if (stat.mtime + mins_in_ns > std.time.nanoTimestamp()) {
            _ = try persist_file.write("0");
            skip_auth = true;
        }
    }

    if (!skip_auth) {
        if (rule.options.sudoku) |cells| {
            var stdin_reader = std.fs.File.stdin().reader(&read_buffer);
            const stdr = &stdin_reader.interface;
            var stdout_writer = std.fs.File.stdout().writer(&write_buffer);
            const stdw = &stdout_writer.interface;

            const completed = playSudoku(cells, stdr, stdw) catch |err| switch (err) {
                error.GenerationFailed => fatal("sudoku generation failed, try increasing cells given in /etc/sudo-kuers", .{}),
                else => return err,
            };
            if (!completed) fatal("sudoku failed", .{});
        }
        if (!rule.options.nopass)
            if (!try authenticate(arena, caller, etc)) fatal("auth failed", .{});

        if (persist_path) |pp| {
            if (std.fs.createFileAbsolute(pp, .{})) |new_persist_file| {
                _ = try new_persist_file.write("0");
                new_persist_file.close();
            } else |err| std.log.warn("failed to make persist file {s}: {t}", .{ pp, err });
        }
    }

    const as_user_info = etc.users.get(as_user) orelse fatal("did not find entry for {s} in /etc/passwd", .{as_user});

    var env_map: std.process.EnvMap = if (rule.options.keepenv)
        .{ .hash_map = try caller.env.hash_map.clone() }
    else
        .init(arena);

    if (rule.options.setenv) |envs| {
        var env_it = mem.tokenizeAny(u8, envs, " \t");
        while (env_it.next()) |env| {
            const eql_pos = mem.indexOfScalar(u8, env, '=');
            const key = env[0 .. eql_pos orelse env.len];
            const val_raw = if (eql_pos) |p| env[p + 1 ..] else "";

            if (val_raw.len > 0 and val_raw[0] == '$') {
                try env_map.put(key, caller.env.get(val_raw[1..]) orelse "");
            } else {
                try env_map.put(key, val_raw);
            }
        }
    }

    if (caller.env.get("TERM")) |term| try env_map.put("TERM", term);
    if (caller.env.get("DISPLAY")) |display| try env_map.put("DISPLAY", display);
    if (caller.env.get("COLORTERM")) |colorterm| try env_map.put("COLORTERM", colorterm);

    if (caller.env.get("PATH")) |path| try env_map.put("PATH", path);
    try env_map.put("USER", as_user);
    try env_map.put("LOGNAME", as_user);
    try env_map.put("HOME", as_user_info.home);
    try env_map.put("SHELL", as_user_info.shell);

    if (!rule.options.nolog) {
        const log_fd = try posix.socket(posix.AF.UNIX, posix.SOCK.DGRAM, 0);
        const log: std.net.Stream = .{ .handle = log_fd };
        defer log.close();

        const log_addr = try std.net.Address.initUnix("/dev/log");
        try posix.connect(log_fd, &log_addr.any, log_addr.getOsSockLen());

        var log_writer = log.writer(&write_buffer);
        try log_writer.interface.print("<5>{s} PWD={s} AS_USER={s} COMMAND={s} {s}", .{
            caller.env.get("USER") orelse "[unknown user]",
            caller.cwd,
            as_user,
            absolute_command,
            try mem.join(arena, " ", argv[1..]),
        });
        try log_writer.interface.flush();
    }

    try posix.setuid(as_user_info.uid);
    try posix.setgid(as_user_info.gid);

    switch (std.process.execve(arena, argv, &env_map)) {
        error.FileNotFound => fatal("command not found", .{}),
        else => |err| fatal("could not execve: {t}", .{err}),
    }
}

const Rule = struct {
    // entire line for the rule is kept in this buffer
    line: []const u8,

    access: enum { permit, deny },
    options: Options = .{},
    identity: union(enum) { user: []const u8, group: []const u8 },
    as_user: ?[]const u8 = null,
    cmd: ?[]const u8 = null,
    args_str: ?[]const u8 = null, // space or \t separated args

    const Options = struct {
        nopass: bool = false,
        nolog: bool = false,
        keepenv: bool = false,
        setenv: ?[]const u8 = null, // space or \t separated key=vals
        sudoku: ?u8 = null,
        persist: ?u32 = null,
    };
};

const RulesIterator = struct {
    reader: *std.Io.Reader,
    line_n: usize = 0,

    /// slices in the previous rule are invalidated after calling next()
    pub fn next(ri: *RulesIterator) error{ReadFailed}!?union(enum) { err_msg: []const u8, rule: Rule } {
        const line = ri.reader.takeDelimiterExclusive('\n') catch |err| switch (err) {
            error.ReadFailed => return error.ReadFailed,
            error.EndOfStream => if (ri.reader.bufferedLen() == 0) {
                return null;
            } else {
                ri.line_n += 1;
                _ = try ri.reader.discardRemaining();
                return .{ .err_msg = "expected newline at end of line" };
            },
            error.StreamTooLong => {
                _ = ri.reader.discardDelimiterInclusive('\n') catch |err2| switch (err2) {
                    error.EndOfStream => {},
                    error.ReadFailed => return error.ReadFailed,
                };
                ri.line_n += 1;
                return .{ .err_msg = "line too long" };
            },
        };
        ri.line_n += 1;

        var rule: Rule = .{ .line = line, .access = undefined, .identity = undefined };

        var it = mem.tokenizeAny(u8, line, "\t ");
        if (it.next()) |ac| {
            if (mem.startsWith(u8, ac, "#")) return ri.next(); //skip command
            if (mem.eql(u8, ac, "permit")) {
                rule.access = .permit;
            } else if (mem.eql(u8, ac, "deny")) {
                rule.access = .deny;
            } else return .{ .err_msg = "expected 'permit' or 'deny' at beginning of line" };
        } else return ri.next(); //skip empty line

        // handle all options
        while (it.next()) |opt| {
            if (mem.eql(u8, opt, "for")) {
                break;
            } else if (mem.eql(u8, opt, "nopass")) {
                rule.options.nopass = true;
            } else if (mem.eql(u8, opt, "nolog")) {
                rule.options.nolog = true;
            } else if (mem.eql(u8, opt, "keepenv")) {
                rule.options.keepenv = true;
            } else if (mem.eql(u8, opt, "setenv")) {
                if (!mem.eql(u8, it.next() orelse "", "{")) return .{ .err_msg = "expected ' { ' after setenv" };
                const start = it.index;
                var last = start;
                while (it.next()) |p| : (last = it.index) {
                    if (mem.eql(u8, p, "}")) break;
                } else return .{ .err_msg = "expected ' } ' after params of setenv" };
                rule.options.setenv = line[start..last];
            } else if (mem.startsWith(u8, opt, "sudoku")) {
                if (opt.len == 6) rule.options.sudoku = 40 else if (opt[6] == '=') {
                    const n = std.fmt.parseInt(u8, opt[7..], 10) catch return .{ .err_msg = "failed to parse u8 number after sudoku=" };
                    if (n < 25 or n > 80) return .{ .err_msg = "n after sudoku= must be between 25 and 80" };
                    rule.options.sudoku = n;
                } else return .{ .err_msg = "unknown option" };
            } else if (mem.startsWith(u8, opt, "persist")) {
                if (opt.len == 7) rule.options.persist = 15 else if (opt[7] == '=') {
                    rule.options.persist = std.fmt.parseInt(u32, opt[8..], 10) catch
                        return .{ .err_msg = "failed to parse u32 number after persist=" };
                } else return .{ .err_msg = "unknown option" };
            } else return .{ .err_msg = "unknown option" };
        } else return .{ .err_msg = "expected 'for' after options" };

        if (it.next()) |id| {
            rule.identity = if (id[0] == ':') .{ .group = id[1..] } else .{ .user = id };
        } else return .{ .err_msg = "expected user or group after 'for'" };

        while (it.next()) |optional| {
            if (mem.eql(u8, optional, "as")) {
                rule.as_user = it.next() orelse return .{ .err_msg = "expected user after 'as'" };
            } else if (mem.eql(u8, optional, "cmd")) {
                rule.cmd = it.next() orelse return .{ .err_msg = "expected command after 'cmd'" };
                if (!std.fs.path.isAbsolute(rule.cmd.?)) return .{ .err_msg = "command must be an absolute path" };
                if (it.next()) |a| {
                    if (!mem.eql(u8, a, "args")) return .{ .err_msg = "expected 'args'" };
                    rule.args_str = it.rest();
                }
                break;
            } else return .{ .err_msg = "expected either 'as' or 'cmd'" };
        }
        return .{ .rule = rule };
    }
};

pub const Caller = struct {
    uid: posix.uid_t,
    groups: std.AutoArrayHashMapUnmanaged(posix.gid_t, void),
    cwd: []const u8,
    env: std.process.EnvMap,

    pub fn stat(arena: mem.Allocator) !Caller {
        const groups_len = linux.getgroups(0, null);
        const groups_buf = try arena.alloc(posix.gid_t, groups_len);
        _ = linux.getgroups(groups_buf.len, @ptrCast(groups_buf));
        const groups: std.AutoArrayHashMapUnmanaged(posix.gid_t, void) = try .init(arena, groups_buf, &.{});

        return .{
            .uid = posix.getuid(),
            .groups = groups,
            .cwd = try std.process.getCwdAlloc(arena),
            .env = try std.process.getEnvMap(arena),
        };
    }
};

pub const Etc = struct {
    groups: std.StringHashMapUnmanaged(posix.gid_t),
    users: std.StringHashMapUnmanaged(User),
    // raw password strings directly from /etc/shadow, (including "!" passwords and empty passwords)
    passwords: std.AutoHashMapUnmanaged(posix.uid_t, []const u8),

    const User = struct {
        uid: posix.uid_t,
        gid: posix.gid_t,
        home: []const u8,
        shell: []const u8,
    };

    // assumes that no files are malformed
    pub fn parse(arena: mem.Allocator) !Etc {
        const group_file = try std.fs.cwd().openFile("/etc/group", .{});
        defer group_file.close();
        var group_reader = group_file.reader(&read_buffer);
        var groups: std.StringHashMapUnmanaged(posix.gid_t) = .empty;
        while (group_reader.interface.peekByte() != error.EndOfStream) {
            const name = try group_reader.interface.takeDelimiterExclusive(':');
            _ = try group_reader.interface.discardDelimiterInclusive(':'); //skip group password field
            const gid_str = try group_reader.interface.takeDelimiterExclusive(':');
            const gid = try std.fmt.parseInt(posix.gid_t, gid_str, 10);
            try groups.put(arena, try arena.dupe(u8, name), gid);
            _ = try group_reader.interface.discardDelimiterInclusive('\n');
        }
        const passwd_file = try std.fs.cwd().openFile("/etc/passwd", .{});
        defer passwd_file.close();
        var passwd_reader = passwd_file.reader(&read_buffer);
        var users: std.StringHashMapUnmanaged(User) = .empty;
        while (passwd_reader.interface.peekByte() != error.EndOfStream) {
            const name = try passwd_reader.interface.takeDelimiterExclusive(':');
            _ = try passwd_reader.interface.discardDelimiterInclusive(':'); //skip password field
            const uid_str = try passwd_reader.interface.takeDelimiterExclusive(':');
            const uid = try std.fmt.parseInt(posix.uid_t, uid_str, 10);
            const gid_str = try passwd_reader.interface.takeDelimiterExclusive(':');
            const gid = try std.fmt.parseInt(posix.gid_t, gid_str, 10);
            _ = try passwd_reader.interface.discardDelimiterInclusive(':'); //skip info field
            const home = try passwd_reader.interface.takeDelimiterExclusive(':');
            const shell = try passwd_reader.interface.takeDelimiterExclusive('\n');
            try users.put(arena, try arena.dupe(u8, name), .{
                .uid = uid,
                .gid = gid,
                .home = try arena.dupe(u8, home),
                .shell = try arena.dupe(u8, shell),
            });
        }
        const shadow_file = try std.fs.cwd().openFile("/etc/shadow", .{});
        defer shadow_file.close();
        var shadow_reader = shadow_file.reader(&read_buffer);
        var passwords: std.AutoHashMapUnmanaged(posix.uid_t, []const u8) = .empty;
        while (shadow_reader.interface.peekByte() != error.EndOfStream) {
            const name = try shadow_reader.interface.takeDelimiterExclusive(':');
            const passwd = try shadow_reader.interface.takeDelimiterExclusive(':');
            try passwords.put(arena, users.get(name).?.uid, try arena.dupe(u8, passwd));
            _ = try shadow_reader.interface.discardDelimiterInclusive('\n');
        }

        return .{ .groups = groups, .users = users, .passwords = passwords };
    }
};
