const std = @import("std");
const build_zon = @import("build.zig.zon");

// Build files in Zig are themselves Zig code!
// This is different from Makefiles or package.json - you get full language power.
pub fn build(b: *std.Build) void { // You must name your build function build.
    // Create build options to pass version to source code
    const options = b.addOptions();
    options.addOption([]const u8, "version", build_zon.version);
    // Add zxing-cpp dependency for QR code generation
    const zxing_dep = b.dependency("zxing_cpp", .{});

    // Get the zxing module and add include path for @cImport
    const zxing_mod = zxing_dep.module("zxing");
    zxing_mod.addSystemIncludePath(b.path("libs/zxing-cpp/core/src"));

    // Add zig-clap dependency for CLI parsing
    const clap = b.dependency("clap", .{});

    // Create age module from the age-ffi Zig bindings
    const age_mod = b.addModule("age", .{
        .root_source_file = b.path("libs/age-ffi/zig/age.zig"),
    });

    // Build zxing-cpp from source using CMake with Zig as C++ compiler
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
        "-DZXING_EXAMPLES=OFF",
        "-DCMAKE_CXX_STANDARD=20",
    });
    // Use Zig as the C and C++ compiler (eliminates need for separate clang++/g++)
    cmake_configure.setEnvironmentVariable("CC", "zig cc");
    cmake_configure.setEnvironmentVariable("CXX", "zig c++");

    const cmake_build = b.addSystemCommand(&.{
        "cmake",
        "--build",
        cmake_build_dir,
        "--config",
        "Release",
        "-j",
    });
    cmake_build.step.dependOn(&cmake_configure.step);

    // Build age-ffi Rust library using Cargo
    const cargo_build = b.addSystemCommand(&.{
        "cargo",
        "build",
        "--release",
        "--manifest-path",
        "libs/age-ffi/Cargo.toml",
    });

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
                .{ .name = "build_options", .module = options.createModule() },
                .{ .name = "age", .module = age_mod },
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

    // Configure age-ffi Rust library
    exe.addLibraryPath(b.path("libs/age-ffi/target/release"));
    exe.addObjectFile(b.path("libs/age-ffi/target/release/libage_ffi.a"));
    if (target.result.os.tag == .macos) {
        // macOS requires Security and CoreFoundation frameworks for Rust crypto
        exe.linkFramework("Security");
        exe.linkFramework("CoreFoundation");
    }
    exe.step.dependOn(&cargo_build.step);

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
                .{ .name = "age", .module = age_mod },
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

    // Configure age-ffi for tests
    unit_tests.addLibraryPath(b.path("libs/age-ffi/target/release"));
    unit_tests.addObjectFile(b.path("libs/age-ffi/target/release/libage_ffi.a"));
    if (target.result.os.tag == .macos) {
        unit_tests.linkFramework("Security");
        unit_tests.linkFramework("CoreFoundation");
    }
    unit_tests.step.dependOn(&cargo_build.step);

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
