const std = @import("std");

// Build files in Zig are themselves Zig code!
// This is different from Makefiles or package.json - you get full language power.

pub fn build(b: *std.Build) void { // You must name your build function build.
    // Add zxing-cpp dependency for QR code generation
    const zxing_dep = b.dependency("zxing_cpp", .{});

    // Get the zxing module and add include path for @cImport
    const zxing_mod = zxing_dep.module("zxing");
    zxing_mod.addSystemIncludePath(b.path("libs/zxing-cpp/core/src"));

    // Add zig-clap dependency for CLI parsing
    const clap = b.dependency("clap", .{});

    // Build zxing-cpp from source using CMake
    const cmake_build_dir = "libs/zxing-cpp/wrappers/zig/zig-out/cmake-build";
    const cmake_configure = b.addSystemCommand(&.{
        "cmake",
        "-S",
        "libs/zxing-cpp",
        "-B",
        cmake_build_dir,
        "-DCMAKE_BUILD_TYPE=Release",
        "-DBUILD_SHARED_LIBS=OFF",
        "-DZXING_READERS=ON",
        "-DZXING_WRITERS=NEW",
        "-DZXING_EXPERIMENTAL_API=ON",
        "-DZXING_C_API=ON",
        "-DZXING_USE_BUNDLED_ZINT=ON",
        "-DCMAKE_CXX_STANDARD=20",
    });

    const cmake_build = b.addSystemCommand(&.{
        "cmake",
        "--build",
        cmake_build_dir,
        "--config",
        "Release",
        "-j",
    });
    cmake_build.step.dependOn(&cmake_configure.step);

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Define our main executable
    const exe = b.addExecutable(.{
        .name = "passage",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zxing", .module = zxing_mod },
                .{ .name = "clap", .module = clap.module("clap") },
            },
        }),
    });

    // Configure zxing-cpp library paths
    exe.addLibraryPath(b.path(cmake_build_dir ++ "/core"));
    exe.linkSystemLibrary("ZXing");
    if (target.result.os.tag == .macos) {
        exe.linkSystemLibrary("c++");
    } else {
        exe.linkSystemLibrary("stdc++");
    }
    exe.linkLibC();
    exe.step.dependOn(&cmake_build.step);

    // This makes `zig build` produce the binary
    b.installArtifact(exe);

    // Create a run step: `zig build run -- [args]`
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run passage");
    run_step.dependOn(&run_cmd.step);

    // Create test step: `zig build test`
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zxing", .module = zxing_mod },
                .{ .name = "clap", .module = clap.module("clap") },
            },
        }),
    });

    // Configure zxing-cpp for tests
    unit_tests.addLibraryPath(b.path(cmake_build_dir ++ "/core"));
    unit_tests.linkSystemLibrary("ZXing");
    if (target.result.os.tag == .macos) {
        unit_tests.linkSystemLibrary("c++");
    } else {
        unit_tests.linkSystemLibrary("stdc++");
    }
    unit_tests.linkLibC();
    unit_tests.step.dependOn(&cmake_build.step);

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
