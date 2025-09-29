const std = @import("std");
const mem = std.mem;
const fatal = std.process.fatal;
const Caller = @import("main.zig").Caller;
const Etc = @import("main.zig").Etc;

const use_pam = @import("config").use_pam;

var stdin_buffer: [4096]u8 = undefined;
var stdout_buffer: [4096]u8 = undefined;

pub const authenticate = if (use_pam) pamAuth else defaultAuth;

fn prompt(msg: []const u8, echo_state: enum { echo_on, echo_off }) ![]u8 {
    const stdin: std.fs.File = .stdin();
    var stdin_reader = stdin.reader(&stdin_buffer);
    const stdout: std.fs.File = .stdout();
    var stdout_writer = stdout.writer(&stdout_buffer);

    try stdout_writer.interface.print("[sudo-ku] {s}", .{msg});
    try stdout_writer.interface.flush();

    const original_termios = try std.posix.tcgetattr(stdin.handle);
    var termios = original_termios;
    termios.lflag.ECHO = echo_state == .echo_on;
    try std.posix.tcsetattr(stdin.handle, .FLUSH, termios);
    defer std.posix.tcsetattr(stdin.handle, .FLUSH, original_termios) catch
        std.log.warn("failed to reset termios", .{});

    const passwd = try stdin_reader.interface.takeDelimiterExclusive('\n');

    try stdout_writer.interface.writeByte('\n');
    try stdout_writer.interface.flush();
    return passwd;
}

const Pam = struct {
    handle: *Handle,

    const Handle = opaque {};
    const Message = extern struct {
        msg_style: c_int,
        msg: [*c]const u8,
    };
    const Response = extern struct {
        resp: [*c]u8,
        resp_retcode: c_int = 0, // unused, expect 0
    };
    const Conv = extern struct {
        conv: ?*const fn (c_int, [*c][*c]const Message, [*c][*c]Response, ?*anyopaque) callconv(.c) c_int,
        appdata_ptr: ?*anyopaque = null,
    };

    extern fn pam_start(service_name: [*c]const u8, user: [*c]const u8, pam_conversation: [*c]const Conv, pamh: [*c]?*Handle) c_int;
    extern fn pam_end(pamh: ?*Handle, pam_status: c_int) c_int;
    extern fn pam_authenticate(pamh: ?*Handle, flags: c_int) c_int;

    pub fn start(service_name: [:0]const u8, user: [:0]const u8, pam_conv: *const Conv) !Pam {
        var h: ?*Handle = null;
        const rc: ReturnCode = @enumFromInt(pam_start(service_name, user, pam_conv, &h));
        if (rc != .SUCCESS) return error.PamStartFailed;
        return .{ .handle = h orelse unreachable };
    }
    pub fn end(p: Pam, status: ReturnCode) void {
        _ = pam_end(p.handle, @intFromEnum(status));
    }
    pub fn authenticate(p: Pam) ReturnCode {
        return @enumFromInt(pam_authenticate(p.handle, 0));
    }

    const MessageStyle = enum(c_int) {
        PROMPT_ECHO_OFF = 1,
        PROMPT_ECHO_ON = 2,
        ERROR_MSG = 3,
        TEXT_INFO = 4,
    };

    const ReturnCode = enum(c_int) {
        SUCCESS = 0, // Successful function return
        OPEN_ERR = 1, // dlopen() failure when dynamically loading a service module
        SYMBOL_ERR = 2, // Symbol not found
        SERVICE_ERR = 3, // Error in service module
        SYSTEM_ERR = 4, // System error
        BUF_ERR = 5, // Memory buffer error
        PERM_DENIED = 6, // Permission denied
        AUTH_ERR = 7, // Authentication failure
        CRED_INSUFFICIENT = 8, // Can not access authentication data due to insufficient credentials
        AUTHINFO_UNAVAIL = 9, // Underlying authentication service can not retrieve authentication information
        USER_UNKNOWN = 10, // User not known to the underlying authentication module
        // An authentication service has maintained a retry count which has
        // been reached.  No further retries should be attempted
        MAXTRIES = 11,
        // New authentication token required. This is normally returned if the
        // machine security policies require that the password should be changed
        // because the password is NULL or it has aged
        NEW_AUTHTOK_REQD = 12,
        ACCT_EXPIRED = 13, // User account has expired
        SESSION_ERR = 14, // Can not make/remove an entry for the specified session
        CRED_UNAVAIL = 15, // Underlying authentication service can not retrieve user credentials unavailable
        CRED_EXPIRED = 16, // User credentials expired
        CRED_ERR = 17, // Failure setting user credentials
        NO_MODULE_DATA = 18, // No module specific data is present
        CONV_ERR = 19, // Conversation error
        AUTHTOK_ERR = 20, // Authentication token manipulation error
        AUTHTOK_RECOVERY_ERR = 21, // Authentication information cannot be recovered
        AUTHTOK_LOCK_BUSY = 22, // Authentication token lock busy
        AUTHTOK_DISABLE_AGING = 23, // Authentication token aging disabled
        TRY_AGAIN = 24, // Preliminary check by password service
        // Ignore underlying account module regardless of whether the control
        // flag is required, optional, or sufficient
        IGNORE = 25,
        ABORT = 26, // Critical error (?module fail now request)
        AUTHTOK_EXPIRED = 27, // user's authentication token has expired
        MODULE_UNKNOWN = 28, // module is not known
        BAD_ITEM = 29, // Bad item passed to pam_*_item()
        CONV_AGAIN = 30, // conversation function is event driven and data is not available yet
        // please call this function again to complete authentication stack.
        //Before calling again, verify that conversation is completed
        INCOMPLETE = 31,
    };
};

fn pamAuth(arena: mem.Allocator, caller: Caller, _: Etc) !bool {
    const user = try arena.dupeZ(u8, caller.env.get("USER") orelse fatal("USER not set", .{}));

    const conv_struct: Pam.Conv = .{ .conv = conv };
    var rc: Pam.ReturnCode = .SUCCESS;

    const pam: Pam = try .start("sudo-ku", user, &conv_struct);
    defer pam.end(rc);

    rc = pam.authenticate();
    return switch (rc) {
        .SUCCESS => true,
        .AUTH_ERR => false,
        else => {
            std.log.err("unexpected pam return code: {t}", .{rc});
            return false;
        },
    };
}

fn conv(
    msg_n: c_int,
    msg: [*c][*c]const Pam.Message,
    res: [*c][*c]Pam.Response,
    _: ?*anyopaque,
) callconv(.c) c_int {
    // have to use the c allocator
    // since pam is responsible for freeing the allocated memory
    const allocator = std.heap.c_allocator;
    const resp_struct_arr = allocator.alloc(Pam.Response, @intCast(msg_n)) catch return @intFromEnum(Pam.ReturnCode.BUF_ERR);
    for (resp_struct_arr) |*m| m.* = .{ .resp = null };
    res.* = resp_struct_arr.ptr;

    for (0..@intCast(msg_n)) |i| {
        const message = mem.span(msg[i].*.msg);
        switch (@as(Pam.MessageStyle, @enumFromInt(msg[i].*.msg_style))) {
            .PROMPT_ECHO_OFF => {
                const stack_pw = prompt(message, .echo_off) catch return @intFromEnum(Pam.ReturnCode.CONV_ERR);
                const pw = allocator.dupeZ(u8, stack_pw) catch return @intFromEnum(Pam.ReturnCode.BUF_ERR);
                res[i].* = .{ .resp = pw.ptr };
            },
            .PROMPT_ECHO_ON => {
                const stack_pw = prompt(message, .echo_on) catch return @intFromEnum(Pam.ReturnCode.CONV_ERR);
                const pw = allocator.dupeZ(u8, stack_pw) catch return @intFromEnum(Pam.ReturnCode.BUF_ERR);
                res[i].* = .{ .resp = pw.ptr };
            },
            .ERROR_MSG => std.log.err("{s}\n", .{message}),
            .TEXT_INFO => std.log.info("{s}\n", .{message}),
        }
    }
    return @intFromEnum(Pam.ReturnCode.SUCCESS);
}

fn defaultAuth(_: mem.Allocator, caller: Caller, etc: Etc) !bool {
    const password_entry = etc.passwords.get(caller.uid) orelse
        fatal("caller has no password entry in /etc/shadow", .{});
    const input_password = try prompt("Password: ", false);
    var hash_buf: [128]u8 = undefined;
    const hash = crypt(input_password, password_entry, &hash_buf) catch |err|
        fatal("crypt error: {t}", .{err});
    if (mem.eql(u8, hash, password_entry)) return true;
    return false;
}

const b64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
fn to64(buf: []u8, u_init: usize) void {
    var u = u_init;
    for (buf) |*b| {
        b.* = b64[u % 64];
        u /= 64;
    }
}

fn hashmd256(ctx: *std.crypto.hash.sha2.Sha256, n: usize, md: []u8) void {
    var i = n;
    while (i > 32) : (i -= 32) ctx.update(md[0..32]);
    ctx.update(md[0..i]);
}
fn hashmd512(ctx: *std.crypto.hash.sha2.Sha512, n: usize, md: []u8) void {
    var i = n;
    while (i > 64) : (i -= 64) ctx.update(md[0..64]);
    ctx.update(md[0..i]);
}

// just copied from musl
fn crypt(key: []const u8, entry: []const u8, buf: []u8) ![]const u8 {
    if (entry.len == 0) return error.PasswordEmpty;
    if (mem.startsWith(u8, entry, "$1$")) {
        const Md5 = std.crypto.hash.Md5;

        const salt = mem.sliceTo(entry[3..], '$');
        var md: [16]u8 = undefined;
        var ctx: Md5 = .init(.{});
        ctx.update(key);
        ctx.update(salt);
        ctx.update(key);
        ctx.final(&md);

        ctx = Md5.init(.{});
        ctx.update(key);
        ctx.update(entry[0 .. salt.len + 3]);
        var i = key.len;
        while (i > 16) : (i -= 16) ctx.update(&md);
        ctx.update(md[0..i]);
        md[0] = 0;
        i = key.len;
        while (i != 0) : (i >>= 1)
            ctx.update(if (i & 1 != 0) md[0..1] else key[0..1]);
        ctx.final(&md);

        for (0..1000) |j| {
            ctx = Md5.init(.{});
            ctx.update(if (j % 2 != 0) key else &md);
            if (j % 3 != 0) ctx.update(salt);
            if (j % 7 != 0) ctx.update(key);
            ctx.update(if (j % 2 != 0) &md else key);
            ctx.final(&md);
        }

        i = salt.len + 4;
        @memcpy(buf[0..i], entry[0..i]);
        const perm = [5][3]u8{
            .{ 0, 6, 12 },
            .{ 1, 7, 13 },
            .{ 2, 8, 14 },
            .{ 3, 9, 15 },
            .{ 4, 10, 5 },
        };
        for (0..5) |j| {
            var u = @as(usize, @intCast(md[perm[j][0]])) << 16;
            u |= @as(usize, @intCast(md[perm[j][1]])) << 8;
            u |= md[perm[j][2]];
            to64(buf[i..][0..4], u);
            i += 4;
        }
        to64(buf[i..][0..2], md[11]);
        i += 2;
        return buf[0..i];
    } else if (mem.startsWith(u8, entry, "$2")) {
        return error.BlowfishUnsupported;
    } else if (mem.startsWith(u8, entry, "$5$")) {
        const Sha256 = std.crypto.hash.sha2.Sha256;
        const next_str = mem.sliceTo(entry[3..], '$');
        var rounds: usize = 5000;
        var salt: []const u8 = "";
        var after_salt: usize = 0;

        if (mem.startsWith(u8, next_str, "rounds=")) {
            rounds = try std.fmt.parseInt(usize, next_str[7..], 10);
            if (rounds > 9999999) rounds = 9999999;
            if (rounds < 1000) rounds = 1000;
            salt = mem.sliceTo(entry[3 + next_str.len + 1 ..], '$');
            after_salt = 3 + next_str.len + 1 + salt.len + 1;
        } else {
            salt = next_str;
            after_salt = 3 + next_str.len + 1;
        }
        var md: [32]u8 = undefined;
        var ctx: Sha256 = .init(.{});
        ctx.update(key);
        ctx.update(salt);
        ctx.update(key);
        ctx.final(&md);

        ctx = Sha256.init(.{});
        ctx.update(key);
        ctx.update(salt);
        hashmd256(&ctx, key.len, &md);
        var i = key.len;
        while (i > 0) : (i >>= 1)
            ctx.update(if (i & 1 != 0) &md else key);
        ctx.final(&md);

        var kmd: [32]u8 = undefined;
        ctx = Sha256.init(.{});
        for (0..key.len) |_| ctx.update(key);
        ctx.final(&kmd);

        var smd: [32]u8 = undefined;
        ctx = Sha256.init(.{});
        for (0..16 + md[0]) |_| ctx.update(salt);
        ctx.final(&smd);

        for (0..rounds) |j| {
            ctx = Sha256.init(.{});
            if (j % 2 != 0) hashmd256(&ctx, key.len, &kmd) else ctx.update(&md);
            if (j % 3 != 0) ctx.update(smd[0..salt.len]);
            if (j % 7 != 0) hashmd256(&ctx, key.len, &kmd);
            if (j % 2 != 0) ctx.update(&md) else hashmd256(&ctx, key.len, &kmd);
            ctx.final(&md);
        }

        @memcpy(buf[0..after_salt], entry[0..after_salt]);
        i = after_salt;

        const perm = [10][3]u8{
            .{ 0, 10, 20 },
            .{ 21, 1, 11 },
            .{ 12, 22, 2 },
            .{ 3, 13, 23 },
            .{ 24, 4, 14 },
            .{ 15, 25, 5 },
            .{ 6, 16, 26 },
            .{ 27, 7, 17 },
            .{ 18, 28, 8 },
            .{ 9, 19, 29 },
        };
        for (0..10) |j| {
            var u = @as(usize, @intCast(md[perm[j][0]])) << 16;
            u |= @as(usize, @intCast(md[perm[j][1]])) << 8;
            u |= md[perm[j][2]];
            to64(buf[i..][0..4], u);
            i += 4;
        }
        to64(buf[i..][0..3], @as(usize, @intCast(md[31])) << 8 | md[30]);
        i += 3;
        return buf[0..i];
    } else if (mem.startsWith(u8, entry, "$6$")) {
        const Sha512 = std.crypto.hash.sha2.Sha512;
        const next_str = mem.sliceTo(entry[3..], '$');
        var rounds: usize = 5000;
        var salt: []const u8 = "";
        var after_salt: usize = 0;

        if (mem.startsWith(u8, next_str, "rounds=")) {
            rounds = try std.fmt.parseInt(usize, next_str[7..], 10);
            if (rounds > 9999999) rounds = 9999999;
            if (rounds < 1000) rounds = 1000;
            salt = mem.sliceTo(entry[3 + next_str.len + 1 ..], '$');
            after_salt = 3 + next_str.len + 1 + salt.len + 1;
        } else {
            salt = next_str;
            after_salt = 3 + next_str.len + 1;
        }
        var md: [64]u8 = undefined;
        var ctx: Sha512 = .init(.{});
        ctx.update(key);
        ctx.update(salt);
        ctx.update(key);
        ctx.final(&md);

        ctx = Sha512.init(.{});
        ctx.update(key);
        ctx.update(salt);
        hashmd512(&ctx, key.len, &md);
        var i = key.len;
        while (i > 0) : (i >>= 1)
            ctx.update(if (i & 1 != 0) &md else key);
        ctx.final(&md);

        var kmd: [64]u8 = undefined;
        ctx = Sha512.init(.{});
        for (0..key.len) |_| ctx.update(key);
        ctx.final(&kmd);

        var smd: [64]u8 = undefined;
        ctx = Sha512.init(.{});
        for (0..16 + md[0]) |_| ctx.update(salt);
        ctx.final(&smd);

        for (0..rounds) |j| {
            ctx = Sha512.init(.{});
            if (j % 2 != 0) hashmd512(&ctx, key.len, &kmd) else ctx.update(&md);
            if (j % 3 != 0) ctx.update(smd[0..salt.len]);
            if (j % 7 != 0) hashmd512(&ctx, key.len, &kmd);
            if (j % 2 != 0) ctx.update(&md) else hashmd512(&ctx, key.len, &kmd);
            ctx.final(&md);
        }

        @memcpy(buf[0..after_salt], entry[0..after_salt]);
        i = after_salt;

        const perm = [21][3]u8{
            .{ 0, 21, 42 },  .{ 22, 43, 1 },  .{ 44, 2, 23 },  .{ 3, 24, 45 },  .{ 25, 46, 4 },
            .{ 47, 5, 26 },  .{ 6, 27, 48 },  .{ 28, 49, 7 },  .{ 50, 8, 29 },  .{ 9, 30, 51 },
            .{ 31, 52, 10 }, .{ 53, 11, 32 }, .{ 12, 33, 54 }, .{ 34, 55, 13 }, .{ 56, 14, 35 },
            .{ 15, 36, 57 }, .{ 37, 58, 16 }, .{ 59, 17, 38 }, .{ 18, 39, 60 }, .{ 40, 61, 19 },
            .{ 62, 20, 41 },
        };
        for (0..21) |j| {
            var u = @as(usize, @intCast(md[perm[j][0]])) << 16;
            u |= @as(usize, @intCast(md[perm[j][1]])) << 8;
            u |= md[perm[j][2]];
            to64(buf[i..][0..4], u);
            i += 4;
        }
        to64(buf[i..][0..2], md[63]);
        i += 2;
        return buf[0..i];
    } else if (mem.startsWith(u8, entry, "!")) {
        return error.PasswordEmpty;
    } else {
        return error.DesUnsupported;
    }
}

test "md5" {
    const testkey = "Xy01@#\x01\x02\x80\x7f\xff\r\n\x81\t !";
    const testhash = "$1$abcd0123$9Qcg8DyviekV3tDGMZynJ1";
    var buf: [128]u8 = undefined;
    const hash = try crypt(testkey, testhash, &buf);
    try std.testing.expectEqualSlices(u8, testhash, hash);
}

test "sha256" {
    const testkey = "Xy01@#\x01\x02\x80\x7f\xff\r\n\x81\t !";
    const testhash = "$5$rounds=1234$abc0123456789$3VfDjPt05VHFn47C/ojFZ6KRPYrOjj1lLbH.dkF3bZ6";
    var buf: [128]u8 = undefined;
    const hash = try crypt(testkey, testhash, &buf);
    try std.testing.expectEqualSlices(u8, testhash, hash);
}

test "sha512" {
    const testkey = "Xy01@#\x01\x02\x80\x7f\xff\r\n\x81\t !";
    const testhash = "$6$rounds=1234$abc0123456789$BCpt8zLrc/RcyuXmCDOE1ALqMXB2MH6n1g891HhFj8.w7LxGv.FTkqq6Vxc/km3Y0jE0j24jY5PIv/oOu6reg1";
    var buf: [128]u8 = undefined;
    const hash = try crypt(testkey, testhash, &buf);
    try std.testing.expectEqualSlices(u8, testhash, hash);
}
