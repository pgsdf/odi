const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const odm_module = b.createModule(.{
        .root_source_file = b.path("src/odm.zig"),
        .target = target,
        .optimize = optimize,
    });

    const odi_module = b.createModule(.{
        .root_source_file = b.path("src/odi.zig"),
        .target = target,
        .optimize = optimize,
    });

    const validate_module = b.createModule(.{
        .root_source_file = b.path("src/validate.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "odi", .module = odi_module },
            .{ .name = "odm", .module = odm_module },
        },
    });

    const exe = b.addExecutable(.{
        .name = "odi",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "odi", .module = odi_module },
                .{ .name = "validate", .module = validate_module },
            },
        }),
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run odi");
    run_step.dependOn(&run_cmd.step);
}


