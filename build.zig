const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const use_pam = !(b.option(bool, "no-pam", "Compile without pam authentication") orelse false);
    const install_sudokuers = !(b.option(bool, "no-sudo-kuers", "don't install default sudo-kuers file") orelse false);

    const exe = b.addExecutable(.{
        .name = "sudo-ku",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = use_pam,
        }),
    });
    const options = b.addOptions();
    options.addOption(bool, "use_pam", use_pam);
    exe.root_module.addOptions("config", options);

    if (use_pam) exe.root_module.linkSystemLibrary("pam", .{});
    if (install_sudokuers) b.installFile("default-sudo-kuers", "etc/sudo-kuers");
    b.installArtifact(exe);
}
