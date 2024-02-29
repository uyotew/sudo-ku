const std = @import("std");
const config = @import("config");
const playSudoku = @import("sudoku.zig").playSudoku;
const eql = std.mem.eql;
const crypt = @cImport(@cInclude("crypt.h")).crypt;
const pam = @import("pam_auth.zig");

pub fn main() !void {
    const pal = std.heap.page_allocator;
    const args = switch (try ArgsRes.parse(pal)) {
        .a => |a| a,
        .parse_err => |err_msg| return usage(err_msg),
        .help => return usage(null),
        .check_conf => |path| {
            // set the effective id to the user id, so
            // the check flag cannot be used too snoop on unowned filed
            try std.os.seteuid(std.os.linux.getuid());
            _ = try parseConfig(pal, path);
            return;
        },
    };
    const rules = try parseConfig(pal, "/etc/sudokuers") orelse return;
    defer pal.free(rules);
    const rule = try matchRule(rules, args) orelse return error.Denied;
    if (rule.opr == .Deny) return error.Denied;

    if (rule.opts.persist) |mins| {
        var file_exists = true;
        const path = try getRulePersistentFilePath(pal, rule);
        defer pal.free(path);
        const fd = std.fs.openFileAbsolute(path, .{ .mode = .write_only }) catch |err| switch (err) {
            error.FileNotFound => l: {
                file_exists = false;
                break :l try std.fs.createFileAbsolute(path, .{});
            },
            else => return err,
        };
        defer fd.close();
        const stat = try fd.stat();
        const mins_in_ns: i128 = @as(i128, @intCast(mins)) * std.time.ns_per_min;
        if (file_exists and stat.mtime + mins_in_ns > std.time.nanoTimestamp()) {
            _ = try fd.write("0");
        } else {
            if (rule.opts.sudoku) |cells| if (!try playSudoku(cells)) return error.Denied;
            if (!rule.opts.nopass) try checkPassword(pal);
            _ = try fd.write("0");
        }
    } else {
        if (rule.opts.sudoku) |cells| if (!try playSudoku(cells)) return error.Denied;
        if (!rule.opts.nopass) try checkPassword(pal);
    }

    var argv = std.ArrayList([]const u8).init(pal);
    try argv.append(args.command);
    try argv.appendSlice(args.cmd_args);
    if (!rule.opts.nolog) {
        const log_addr = try std.net.Address.initUnix("/dev/log");
        const fd = try std.os.socket(std.os.AF.UNIX, std.os.SOCK.DGRAM, 0);
        defer std.os.closeSocket(fd);

        var cwd_buf: [std.os.PATH_MAX]u8 = undefined;
        const message = try std.fmt.allocPrint(pal, "<5>{s} PWD={s} USER={s} COMMAND={s}", .{
            try getUsernameFromId(pal, std.os.linux.getuid()),
            try std.os.getcwd(&cwd_buf),
            args.user,
            try std.mem.join(pal, " ", argv.items),
        });
        defer pal.free(message);
        _ = try std.os.sendto(fd, message, 0, &log_addr.any, log_addr.getOsSockLen());
    }

    const user_info = try std.process.posixGetUserInfo(args.user);
    try std.os.setuid(user_info.uid);
    try std.os.setgid(user_info.gid);

    return switch (std.process.execv(pal, argv.items)) {
        error.FileNotFound => error.CommandNotFound,
        else => |e| e,
    };
}

fn getRulePersistentFilePath(pal: std.mem.Allocator, rule: Rule) ![]const u8 {
    std.fs.makeDirAbsolute("/tmp/sudo-ku") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const serialized = try rule.serialize(pal);
    defer pal.free(serialized);
    const hash_raw = std.hash.Wyhash.hash(342912, serialized);
    const encoder = std.base64.url_safe.Encoder;
    var hash_buf: [encoder.calcSize(8)]u8 = undefined;
    const hash = encoder.encode(&hash_buf, &@as([8]u8, @bitCast(hash_raw)));
    return try std.mem.concat(pal, u8, &.{ "/tmp/sudo-ku/", hash });
}

/// errors if unable to authenticate
fn checkPassword(pal: std.mem.Allocator) !void {
    const user = try getUsernameFromId(pal, std.os.linux.getuid());
    defer pal.free(user);

    if (config.pam) {
        return try pam.authenticate(user);
    } else {
        const pwd_c = blk: {
            var buf: [2048]u8 = undefined;
            break :blk try getPasswordFromUser(&buf);
        };
        const entry_c = try getShadowEntry(pal, user);
        defer pal.free(entry_c);
        const pwd_hash = crypt(pwd_c, entry_c);
        if (eql(u8, std.mem.span(pwd_hash), entry_c)) return;
        return error.Denied;
    }
}
fn getPasswordFromUser(buf: []u8) ![:0]const u8 {
    const w = std.io.getStdOut().writer();
    const r = std.io.getStdIn().reader();
    try w.writeAll("[sudo-ku] Password: ");
    const original_termios = try std.os.tcgetattr(0);
    try std.os.tcsetattr(0, .FLUSH, blk: {
        var termios = original_termios;
        termios.lflag &= ~std.os.linux.ECHO;
        break :blk termios;
    });
    const len = try r.read(buf);
    try std.os.tcsetattr(0, .FLUSH, original_termios);
    try w.writeAll("\n");

    if (len == buf.len) return error.PasswordTooLong;
    // replace the newline from the input with a 0
    std.debug.assert(len > 0);
    buf[len - 1] = 0;
    return buf[0 .. len - 1 :0];
}

pub fn getUsernameFromId(pal: std.mem.Allocator, id: std.os.uid_t) ![:0]const u8 {
    var f = try std.fs.openFileAbsolute("/etc/passwd", .{});
    defer f.close();
    const buf = try f.readToEndAlloc(pal, 1 << 16);
    defer pal.free(buf);
    var line_it = std.mem.splitScalar(u8, buf, '\n');
    const err = error.CorruptedPasswdFile;
    while (line_it.next()) |line| {
        var it = std.mem.splitScalar(u8, line, ':');
        const user = it.next() orelse return err;
        _ = it.next() orelse return err;
        const id_str = it.next() orelse return err;
        if (try std.fmt.parseUnsigned(std.os.uid_t, id_str, 10) == id) {
            return try pal.dupeZ(u8, user);
        } else continue;
    }
    return error.UserNotFound;
}

fn getShadowEntry(pal: std.mem.Allocator, name: []const u8) ![:0]const u8 {
    var f = try std.fs.openFileAbsolute("/etc/shadow", .{});
    defer f.close();
    const buf = try f.readToEndAlloc(pal, 1 << 16);
    defer pal.free(buf);
    var line_it = std.mem.splitScalar(u8, buf, '\n');
    const err = error.CorruptedShadowFile;
    while (line_it.next()) |line| {
        var it = std.mem.splitScalar(u8, line, ':');
        const user = it.next() orelse return err;
        if (!eql(u8, user, name)) continue;
        const pwd = it.next() orelse return err;
        if (pwd[0] == '!' or pwd[0] == '*') return error.UserHasNoPassword;
        return try pal.dupeZ(u8, pwd);
    }
    return error.UserNotFound;
}

fn getGroupId(name: []const u8) !std.os.gid_t {
    var f = try std.fs.openFileAbsolute("/etc/group", .{});
    defer f.close();
    var buf: [std.mem.page_size]u8 = undefined;
    var name_i: usize = 0;
    var colon_n: usize = 0;
    var cnt = false;
    var id: std.os.gid_t = 0;
    outer: while (true) {
        const len = try f.read(&buf);
        if (len == 0) break;
        for (buf[0..len]) |b| {
            if (cnt) {
                if (b == '\n') cnt = false;
                continue;
            }
            if (colon_n == 2) {
                if (b == ':') break :outer;
                id *= 10;
                id += b - '0';
                continue;
            }
            if (b == ':' and name_i == name.len) {
                colon_n += 1;
                continue;
            }
            if (colon_n == 1) continue;
            if (name_i < name.len and b == name[name_i]) {
                name_i += 1;
                continue;
            }
            name_i = 0;
            cnt = true;
        }
    }
    return id;
}

fn matchRule(rules: []const Rule, args: ArgsRes.Args) !?Rule {
    const user = std.os.linux.getuid();
    var groups: [256]std.os.gid_t = undefined;
    const g_len = std.os.linux.getgroups(256, @ptrCast(&groups));
    if (g_len < 0) return error.ErrorGettingGroups;

    return top: for (rules) |r| {
        if (switch (r.idt) {
            .user => |u| (try std.process.posixGetUserInfo(u)).uid != user,
            .group => |g_name| blk: {
                const g_id = try getGroupId(g_name);
                for (0..g_len) |i| {
                    if (groups[i] == g_id) break :blk false;
                } else break :blk true;
            },
        }) continue;
        if (r.as_user) |u| if (!eql(u8, args.user, u)) continue;
        if (r.cmd) |c| {
            if (!eql(u8, c, args.command)) continue;
            if (r.args) |a| {
                if (a.len != args.cmd_args.len) continue;
                for (a, args.cmd_args) |ra, ca| if (!eql(u8, ra, ca)) continue :top;
            }
        }
        break r;
    } else null;
}

fn parseConfig(pal: std.mem.Allocator, path: []const u8) !?[]const Rule {
    const buf = blk: {
        const f = try std.fs.cwd().openFile(path, .{});
        defer f.close();
        break :blk try f.readToEndAlloc(pal, 1 << 16);
    };
    defer pal.free(buf);
    var list = std.ArrayList(Rule).init(pal);
    var it = std.mem.splitScalar(u8, buf, '\n');
    var line_n: usize = 1;
    while (it.next()) |line| : (line_n += 1) {
        const l = std.mem.trim(u8, line, "\t ");
        if (l.len == 0) continue;
        if (l[0] == '#') continue;
        switch (try Rule.parse(line, pal)) {
            .rule => |r| try list.append(r),
            .err => |e| {
                var p = try pal.alloc(u8, if (e.c > 0) e.c else 1);
                defer pal.free(p);
                @memset(p, ' ');
                p[p.len - 1] = '^';
                std.log.err("{s} in file: {s}:{}:{}\n{s}\n{s}", .{ @errorName(e.err), path, line_n, e.c, line, p });
                return null;
            },
        }
    }
    return try list.toOwnedSlice();
}

const Rule = struct {
    const Opr = enum { Permit, Deny };
    const Options = struct {
        nopass: bool = false,
        sudoku: ?u8 = null,
        nolog: bool = false,
        persist: ?u32 = null,
    };
    const Identity = union(enum) {
        user: []const u8,
        group: []const u8,
    };
    opr: Opr,
    opts: Options = .{},
    idt: Identity,
    as_user: ?[]const u8 = null,
    cmd: ?[]const u8 = null,
    args: ?[]const []const u8 = null,

    pub const ParseRet = union(enum) {
        rule: Rule,
        err: struct { err: anyerror, c: usize },

        fn e(i: usize, err: anyerror) ParseRet {
            return .{ .err = .{ .err = err, .c = i + 1 } };
        }
    };
    /// only called before hashing
    /// asserts that rule.opts.persist is not null
    pub fn serialize(rule: Rule, pal: std.mem.Allocator) ![]u8 {
        var lst = std.ArrayList(u8).init(pal);
        try lst.append(@intFromEnum(rule.opr));
        try lst.append(@intFromBool(rule.opts.nopass));
        try lst.append(@intFromBool(rule.opts.nolog));
        std.debug.assert(rule.opts.sudoku orelse 1 > 0);
        try lst.append(rule.opts.sudoku orelse 0);
        try lst.appendSlice(&@as([4]u8, @bitCast(rule.opts.persist.?)));
        switch (rule.idt) {
            .user => |u| {
                try lst.append(0);
                try lst.appendSlice(u);
            },
            .group => |g| {
                try lst.append(1);
                try lst.appendSlice(g);
            },
        }
        try lst.append(@intFromBool(rule.as_user == null));
        if (rule.as_user) |u| try lst.appendSlice(u);
        try lst.append(@intFromBool(rule.cmd == null));
        if (rule.cmd) |c| try lst.appendSlice(c);
        try lst.append(@intFromBool(rule.args == null));
        if (rule.args) |args| for (args) |a| {
            try lst.appendSlice(a);
            try lst.append(0);
        };
        return try lst.toOwnedSlice();
    }

    pub fn parse(line: []const u8, pal: std.mem.Allocator) !ParseRet {
        var it = std.mem.tokenizeAny(u8, line, "\t ");
        const e = ParseRet.e;

        const opr: Opr = blk: {
            const err = error.ExpectedPermitOrDeny;
            const b = it.next() orelse return e(0, err);
            if (eql(u8, b, "permit")) break :blk .Permit;
            if (eql(u8, b, "deny")) break :blk .Deny;
            return e(it.index - b.len, err);
        };
        const opts = blk: {
            var o: Rule.Options = .{};
            while (it.next()) |b| {
                if (eql(u8, b, "for")) {
                    break;
                } else if (eql(u8, b, "nopass")) {
                    o.nopass = true;
                } else if (eql(u8, b, "nolog")) {
                    o.nolog = true;
                } else if (std.mem.startsWith(u8, b, "persist")) {
                    if (b.len == 7) o.persist = 15 else if (b[7] == '=') {
                        const n = std.fmt.parseUnsigned(u32, b[8..], 10);
                        o.persist = n catch |err| return e(it.index - b.len + 8, err);
                    } else return e(it.index - b.len, error.InvalidOption);
                } else if (std.mem.startsWith(u8, b, "sudoku")) {
                    if (b.len == 6) o.sudoku = 40 else if (b[6] == '=') {
                        const n = std.fmt.parseUnsigned(u8, b[7..], 10);
                        o.sudoku = n catch return e(it.index - b.len + 7, error.InvalidNumber);
                    } else return e(it.index - b.len, error.InvalidOption);
                    if (o.sudoku.? > 80 or o.sudoku.? < 20) {
                        return e(it.index - b.len + 7, error.InvalidNumberOfSudokuCells);
                    }
                } else return e(it.index - b.len, error.InvalidOption);
            } else return e(it.index + 1, error.ExpectedFor);
            break :blk o;
        };
        const idt: Identity = blk: {
            const b = it.next() orelse return e(it.index + 1, error.ExpectedIdentity);
            if (std.mem.startsWith(u8, b, ":")) break :blk .{ .group = try pal.dupe(u8, b[1..]) };
            break :blk .{ .user = try pal.dupe(u8, b) };
        };
        const as_user = blk: {
            if (eql(u8, it.peek() orelse "", "as")) {
                _ = it.next();
                const u = it.next() orelse return e(it.index + 1, error.ExpectedTarget);
                break :blk try pal.dupe(u8, u);
            } else break :blk null;
        };
        const cmd = blk: {
            if (eql(u8, it.peek() orelse "", "cmd")) {
                _ = it.next();
                const c = it.next() orelse return e(it.index + 1, error.ExpectedCommand);
                break :blk try pal.dupe(u8, c);
            } else break :blk null;
        };
        const args = blk: {
            if (cmd != null and eql(u8, it.peek() orelse "", "args")) {
                _ = it.next();
                var list = std.ArrayList([]const u8).init(pal);
                while (it.next()) |a| try list.append(try pal.dupe(u8, a));
                break :blk try list.toOwnedSlice();
            } else break :blk null;
        };
        if (it.peek() != null) return e(it.index, error.ExpectedEndOfLine);
        return .{ .rule = Rule{
            .opr = opr,
            .opts = opts,
            .idt = idt,
            .as_user = as_user,
            .cmd = cmd,
            .args = args,
        } };
    }
};

const ArgsRes = union(enum) {
    const Args = struct {
        command: []const u8 = undefined,
        cmd_args: []const []const u8 = &[0][]u8{},
        user: []const u8 = "root",
    };
    a: Args,
    parse_err: []const u8,
    help,
    check_conf: []const u8,

    pub fn parse(pal: std.mem.Allocator) !ArgsRes {
        var arg_buf = try std.process.argsAlloc(pal);
        if (arg_buf.len < 2) return .{ .parse_err = "No command specified" };
        var args = ArgsRes.Args{};

        var i: usize = 1;
        while (i < arg_buf.len) : (i += 1) {
            const a = arg_buf[i];
            if (!std.mem.startsWith(u8, a, "-")) {
                args.command = a;
                if (arg_buf.len > i + 1) {
                    args.cmd_args = arg_buf[i + 1 ..];
                }
                break;
            }
            if (eql(u8, a, "--")) {
                if (arg_buf.len > i + 1) {
                    args.command = arg_buf[i + 1];
                    if (arg_buf.len > i + 2) {
                        args.cmd_args = arg_buf[i + 2 ..];
                    }
                    break;
                } else return .{ .parse_err = "No command specified" };
            }
            for (1..a.len) |j| {
                switch (a[j]) {
                    'h' => return .{ .help = {} },
                    'u' => if (arg_buf.len > i + 1) {
                        i += 1;
                        args.user = arg_buf[i];
                    } else return .{ .parse_err = "No user specified" },
                    'c' => if (arg_buf.len > i + 1) {
                        i += 1;
                        return .{ .check_conf = arg_buf[i] };
                    } else return .{ .parse_err = "No file specified" },
                    else => return .{
                        .parse_err = try std.fmt.allocPrint(pal, "{c} is not an option", .{a[j]}),
                    },
                }
            }
        }
        return .{ .a = args };
    }
};

fn usage(err: ?[]const u8) void {
    const name = blk: {
        var it = std.process.args();
        break :blk it.next();
    };

    if (err) |e| std.log.err("{s}\n", .{e});
    std.log.info(
        \\Usage: {?s} [Options] [--] command
        \\Options:
        \\ -h                  help
        \\ -u user             run command as user (default root)
        \\ -c sudokuers-file   check/verify syntax of sudokuers-file
        \\ --                  stop parsing of options
        \\
    , .{name});
}
