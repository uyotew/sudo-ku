const std = @import("std");
const getUsernameFromId = @import("src/main.zig").getUsernameFromId;

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const pam = b.option(bool, "pam", "Compile with pam authentication") orelse false;

    const exe = b.addExecutable(.{
        .name = "sudo-ku",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    const options = b.addOptions();
    options.addOption(bool, "pam", pam);
    exe.root_module.addOptions("config", options);

    exe.linkLibC();
    if (pam) {
        exe.linkSystemLibrary("pam");
    } else {
        exe.linkSystemLibrary("crypt");
    }

    const install = b.addInstallArtifact(exe, .{});
    const add_setuid_bit = b.addSystemCommand(&.{
        "chmod",
        "4755",
        b.getInstallPath(.bin, exe.out_filename),
    });
    add_setuid_bit.step.dependOn(&install.step);
    b.getInstallStep().dependOn(&add_setuid_bit.step);

    const sudokuers_file = b.step("gen", "Generates a sudokuers file granting root permissions for the current user");
    const user = try getUsernameFromId(b.allocator, std.os.linux.getuid());
    const write_sudokuers_file = b.addWriteFile("sudokuers", b.fmt("permit for {s}", .{user}));
    const install_sudokuers_file = b.addInstallFile(write_sudokuers_file.files.items[0].getPath(), "sudokuers");
    install_sudokuers_file.step.dependOn(&write_sudokuers_file.step);
    sudokuers_file.dependOn(&install_sudokuers_file.step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
