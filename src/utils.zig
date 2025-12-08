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

/// Ensure parent directories exist for the given path
pub fn ensureParentDir(path: []const u8) !void {
    if (std.fs.path.dirname(path)) |parent| {
        fs.makeDirAbsolute(parent) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };
    }
}

/// Extract a specific line from content (default to first line)
pub fn extractLine(content: []const u8, line: ?u32) []const u8 {
    const target_line = line orelse 1;
    var lines = mem.splitSequence(u8, content, "\n");
    var current: u32 = 1;

    while (lines.next()) |l| {
        if (current == target_line) {
            return l;
        }
        current += 1;
    }

    // Default to first line if not found
    return if (mem.indexOf(u8, content, "\n")) |idx| content[0..idx] else content;
}

// Saved terminal state for restoration
var saved_termios: ?std.posix.termios = null;

/// Disable terminal echo for password entry
/// Saves original terminal state so it can be restored
pub fn disableEcho() void {
    switch (comptime builtin.os.tag) {
        .linux, .macos, .freebsd, .openbsd, .netbsd => {
            // Save original terminal state for restoration
            saved_termios = std.posix.tcgetattr(std.posix.STDIN_FILENO) catch return;

            var termios = saved_termios.?;
            termios.lflag.ECHO = false;
            std.posix.tcsetattr(std.posix.STDIN_FILENO, .FLUSH, termios) catch {};
        },
        else => {},
    }
}

/// Re-enable terminal echo by restoring saved state
pub fn enableEcho() void {
    switch (comptime builtin.os.tag) {
        .linux, .macos, .freebsd, .openbsd, .netbsd => {
            // Restore saved state if available, otherwise just enable echo
            if (saved_termios) |termios| {
                std.posix.tcsetattr(std.posix.STDIN_FILENO, .FLUSH, termios) catch {};
                saved_termios = null;
            } else {
                var termios = std.posix.tcgetattr(std.posix.STDIN_FILENO) catch return;
                termios.lflag.ECHO = true;
                std.posix.tcsetattr(std.posix.STDIN_FILENO, .FLUSH, termios) catch {};
            }
        },
        else => {},
    }
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
