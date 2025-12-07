const std = @import("std");
const builtin = @import("builtin");
const fs = std.fs;
const mem = std.mem;

pub const Error = error{
    SneakyPath,
};

/// Securely wipe sensitive data from memory before freeing
/// Uses volatile write to prevent compiler optimization
pub fn secureWipe(slice: []u8) void {
    @memset(slice, 0);
    // Prevent compiler from optimizing away the memset
    std.mem.doNotOptimizeAway(slice.ptr);
}

/// Securely free sensitive data (wipe then free)
pub fn secureFree(allocator: std.mem.Allocator, slice: []u8) void {
    secureWipe(slice);
    allocator.free(slice);
}

/// Check for sneaky path traversal attempts (../) and other malicious paths
pub fn checkSneakyPaths(path: []const u8) !void {
    // Reject absolute paths - passwords must be relative to store
    if (std.fs.path.isAbsolute(path)) {
        return Error.SneakyPath;
    }

    // Reject embedded null bytes (could truncate path in C libraries)
    if (mem.indexOfScalar(u8, path, 0) != null) {
        return Error.SneakyPath;
    }

    // Check for various forms of path traversal
    if (mem.startsWith(u8, path, "../") or
        mem.endsWith(u8, path, "/..") or
        mem.indexOf(u8, path, "/../") != null or
        mem.eql(u8, path, ".."))
    {
        return Error.SneakyPath;
    }
}

/// Get secure temp directory (prefer /dev/shm on Linux)
pub fn getSecureTmpDir() []const u8 {
    switch (comptime builtin.os.tag) {
        .linux => {
            // Check if /dev/shm exists and is writable
            if (fs.accessAbsolute("/dev/shm", .{ .mode = .read_write })) |_| {
                return "/dev/shm";
            } else |_| {}
        },
        else => {},
    }
    // Fall back to TMPDIR or /tmp
    return std.posix.getenv("TMPDIR") orelse "/tmp";
}

// =============================================================================
// TESTS
// =============================================================================

test "checkSneakyPaths detects path traversal" {
    // Path traversal attempts should fail
    try std.testing.expectError(Error.SneakyPath, checkSneakyPaths("../etc/passwd"));
    try std.testing.expectError(Error.SneakyPath, checkSneakyPaths("foo/../bar"));
    try std.testing.expectError(Error.SneakyPath, checkSneakyPaths("foo/.."));
    try std.testing.expectError(Error.SneakyPath, checkSneakyPaths(".."));

    // Absolute paths should fail
    try std.testing.expectError(Error.SneakyPath, checkSneakyPaths("/etc/passwd"));
    try std.testing.expectError(Error.SneakyPath, checkSneakyPaths("/tmp/secret"));

    // Null byte injection should fail
    try std.testing.expectError(Error.SneakyPath, checkSneakyPaths("foo\x00bar"));
    try std.testing.expectError(Error.SneakyPath, checkSneakyPaths("password\x00/../etc/passwd"));

    // These should pass (legitimate password names)
    try checkSneakyPaths("foo/bar");
    try checkSneakyPaths("foo.bar");
    try checkSneakyPaths("foo..bar");
    try checkSneakyPaths("..foo");
    try checkSneakyPaths("foo..");
    try checkSneakyPaths("email/work");
    try checkSneakyPaths("sites/github.com");
}

test "getSecureTmpDir returns valid directory" {
    const tmpdir = getSecureTmpDir();
    try std.testing.expect(tmpdir.len > 0);

    // Should be accessible
    fs.accessAbsolute(tmpdir, .{}) catch {
        // If we can't access it, the test should fail
        try std.testing.expect(false);
    };
}
