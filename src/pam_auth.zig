const std = @import("std");
const pam_c = @cImport({
    @cInclude("security/pam_appl.h");
});
// PAM will send more detailed error messages to the system log
// check it if any of these errors occur
pub fn authenticate(user: [:0]const u8) !void {
    var handle: ?*pam_c.pam_handle_t = undefined;
    const conv_struct: pam_c.struct_pam_conv = .{ .conv = conv };
    var rc = pam_c.PAM_SUCCESS;

    defer if (pam_c.pam_end(handle, rc) != pam_c.PAM_SUCCESS) unreachable;

    rc = pam_c.pam_start("sudo-ku", user, &conv_struct, &handle);
    if (rc != pam_c.PAM_SUCCESS) return error.PamStartFailed;

    rc = pam_c.pam_authenticate(handle, 0);
    return switch (rc) {
        pam_c.PAM_SUCCESS => {},
        pam_c.PAM_ABORT => error.PamAbort,
        pam_c.PAM_AUTH_ERR => error.PamAuthErr,
        pam_c.PAM_CRED_INSUFFICIENT => error.PamCredInsufficient,
        pam_c.PAM_AUTHINFO_UNAVAIL => error.PamAuthinfoUnavail,
        pam_c.PAM_MAXTRIES => error.PamMaxtries,
        pam_c.PAM_USER_UNKNOWN => error.PamUserUnknown,
        else => error.PamUnexpected,
    };
}

fn conv(
    msg_n: c_int,
    msg: [*c][*c]const pam_c.struct_pam_message,
    res: [*c][*c]pam_c.struct_pam_response,
    _: ?*anyopaque,
) callconv(.C) c_int {
    const resp_struct_arr = std.heap.c_allocator.alloc(pam_c.struct_pam_response, @intCast(msg_n)) catch return pam_c.PAM_BUF_ERR;
    const resp_msg_arr = std.heap.c_allocator.alloc(?[:0]u8, @intCast(msg_n)) catch return pam_c.PAM_BUF_ERR;
    defer std.heap.c_allocator.free(resp_msg_arr);

    for (0..@intCast(msg_n)) |i| {
        const message = std.mem.span(msg[i].*.msg);
        var err = false;
        resp_msg_arr[i] = switch (msg[i].*.msg_style) {
            pam_c.PAM_PROMPT_ECHO_OFF => prompt(message, false) catch l: {
                err = true;
                break :l null;
            },
            pam_c.PAM_PROMPT_ECHO_ON => prompt(message, true) catch l: {
                err = true;
                break :l null;
            },
            pam_c.PAM_ERROR_MSG => l: {
                std.log.err("{s}\n", .{message});
                break :l null;
            },
            pam_c.PAM_TEXT_INFO => l: {
                std.log.info("{s}\n", .{message});
                break :l null;
            },
            else => unreachable,
        };
        if (err) {
            for (0..i) |j| if (resp_msg_arr[j]) |r| {
                std.heap.c_allocator.free(r);
            };
            std.heap.c_allocator.free(resp_struct_arr);
            return pam_c.PAM_CONV_ERR;
        }
    }

    for (resp_struct_arr, resp_msg_arr) |*r, m| {
        r.resp_retcode = 0;
        r.resp = if (m) |b| b.ptr else null;
    }
    res.* = resp_struct_arr.ptr;
    return pam_c.PAM_SUCCESS;
}

fn prompt(msg: []const u8, echo: bool) ![:0]u8 {
    const w = std.io.getStdOut().writer();
    const r = std.io.getStdIn().reader();

    try w.print("[sudo-ku] {s}", .{msg});

    const og_termios = if (!echo) b: {
        const original_termios = try std.os.tcgetattr(0);
        var termios = original_termios;
        termios.lflag &= ~std.os.linux.ECHO;
        try std.os.tcsetattr(0, .FLUSH, termios);
        break :b original_termios;
    } else null;

    var lst = std.ArrayList(u8).init(std.heap.c_allocator);
    errdefer lst.deinit();
    try r.streamUntilDelimiter(lst.writer(), '\n', null);

    try w.writeByte('\n');

    if (og_termios) |t| try std.os.tcsetattr(0, .FLUSH, t);

    return lst.toOwnedSliceSentinel(0);
}
