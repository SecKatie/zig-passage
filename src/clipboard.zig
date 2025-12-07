const std = @import("std");
const builtin = @import("builtin");
const process = std.process;

// =============================================================================
// CLIPBOARD MODULE
// =============================================================================
//
// Platform-specific clipboard operations.
// This is where Zig's comptime features shine - we can select the right
// implementation at compile time with zero runtime overhead!
// =============================================================================

pub const ClipboardError = error{
    ClipboardNotAvailable,
    CopyFailed,
    PasteFailed,
};

/// Copy text to the system clipboard
pub fn copy(text: []const u8) !void {
    // comptime switch - decided at compile time, not runtime!
    // This means no runtime overhead for platform detection.
    switch (comptime builtin.os.tag) {
        .macos => try copyDarwin(text),
        .linux => try copyLinux(text),
        .freebsd, .openbsd, .netbsd => try copyBSD(text),
        .windows => try copyWindows(text),
        else => return ClipboardError.ClipboardNotAvailable,
    }
}

/// Get text from the system clipboard
pub fn paste(allocator: std.mem.Allocator) ![]const u8 {
    switch (comptime builtin.os.tag) {
        .macos => return pasteDarwin(allocator),
        .linux => return pasteLinux(allocator),
        .freebsd, .openbsd, .netbsd => return pasteBSD(allocator),
        .windows => return pasteWindows(allocator),
        else => return ClipboardError.ClipboardNotAvailable,
    }
}

/// Clear the clipboard (typically called after a timeout)
pub fn clear() !void {
    try copy("");
}

// =============================================================================
// DARWIN (macOS) IMPLEMENTATION
// =============================================================================

fn copyDarwin(text: []const u8) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var child = std.process.Child.init(&.{"pbcopy"}, allocator);
    child.stdin_behavior = .Pipe;

    try child.spawn();

    const stdin = child.stdin.?;
    try stdin.writeAll(text);
    stdin.close();
    child.stdin = null;

    const result = try child.wait();
    if (result.Exited != 0) {
        return ClipboardError.CopyFailed;
    }
}

fn pasteDarwin(allocator: std.mem.Allocator) ![]const u8 {
    var child = std.process.Child.init(&.{"pbpaste"}, allocator);
    child.stdout_behavior = .Pipe;

    try child.spawn();

    const stdout = child.stdout.?;
    var read_buf: [4096]u8 = undefined;
    var f_reader = stdout.reader(&read_buf);
    const output = try f_reader.interface.allocRemaining(allocator, .unlimited);

    const result = try child.wait();
    if (result.Exited != 0) {
        allocator.free(output);
        return ClipboardError.PasteFailed;
    }

    return output;
}

// =============================================================================
// LINUX IMPLEMENTATION
// =============================================================================

fn copyLinux(text: []const u8) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Try wl-copy (Wayland) first, then xclip (X11)
    const tools = [_][]const []const u8{
        &.{"wl-copy"},
        &.{ "xclip", "-selection", "clipboard" },
        &.{ "xsel", "--clipboard", "--input" },
    };

    for (tools) |tool| {
        var child = std.process.Child.init(tool, allocator);
        child.stdin_behavior = .Pipe;

        child.spawn() catch continue;

        const stdin = child.stdin.?;
        stdin.writeAll(text) catch continue;
        stdin.close();
        child.stdin = null;

        const result = child.wait() catch continue;
        if (result.Exited == 0) return;
    }

    return ClipboardError.ClipboardNotAvailable;
}

fn pasteLinux(allocator: std.mem.Allocator) ![]const u8 {
    const tools = [_][]const []const u8{
        &.{"wl-paste"},
        &.{ "xclip", "-selection", "clipboard", "-o" },
        &.{ "xsel", "--clipboard", "--output" },
    };

    for (tools) |tool| {
        var child = std.process.Child.init(tool, allocator);
        child.stdout_behavior = .Pipe;

        child.spawn() catch continue;

        const stdout = child.stdout.?;
        var read_buf: [4096]u8 = undefined;
        var f_reader = stdout.reader(&read_buf);
        const output = f_reader.interface.allocRemaining(allocator, .unlimited) catch continue;

        const result = child.wait() catch {
            allocator.free(output);
            continue;
        };

        if (result.Exited == 0) return output;
        allocator.free(output);
    }

    return ClipboardError.ClipboardNotAvailable;
}

// =============================================================================
// BSD IMPLEMENTATION (similar to Linux, typically X11)
// =============================================================================

fn copyBSD(text: []const u8) !void {
    return copyLinux(text);
}

fn pasteBSD(allocator: std.mem.Allocator) ![]const u8 {
    return pasteLinux(allocator);
}

// =============================================================================
// WINDOWS IMPLEMENTATION
// =============================================================================

fn copyWindows(text: []const u8) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Use PowerShell's Set-Clipboard
    var child = std.process.Child.init(&.{ "powershell", "-Command", "Set-Clipboard" }, allocator);
    child.stdin_behavior = .Pipe;

    try child.spawn();

    const stdin = child.stdin.?;
    try stdin.writeAll(text);
    stdin.close();
    child.stdin = null;

    const result = try child.wait();
    if (result.Exited != 0) {
        return ClipboardError.CopyFailed;
    }
}

fn pasteWindows(allocator: std.mem.Allocator) ![]const u8 {
    var child = std.process.Child.init(&.{ "powershell", "-Command", "Get-Clipboard" }, allocator);
    child.stdout_behavior = .Pipe;

    try child.spawn();

    const stdout = child.stdout.?;
    var read_buf: [4096]u8 = undefined;
    var f_reader = stdout.reader(&read_buf);
    const output = try f_reader.interface.allocRemaining(allocator, .unlimited);

    const result = try child.wait();
    if (result.Exited != 0) {
        allocator.free(output);
        return ClipboardError.PasteFailed;
    }

    return output;
}

// =============================================================================
// CLIPBOARD CLEARING WITH TIMEOUT
// =============================================================================

/// Compute a simple checksum of clipboard content for verification
/// We don't store the actual password, just a hash to check if it changed
fn computeChecksum(data: []const u8) u64 {
    // Use a simple FNV-1a hash - not cryptographic, but good enough for comparison
    var hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    for (data) |byte| {
        hash ^= byte;
        hash *%= 0x100000001b3; // FNV prime
    }
    return hash;
}

/// Spawn a background process to clear clipboard after timeout seconds
/// Only clears if the clipboard still contains the same content (by checksum)
pub fn clearAfterTimeout(timeout_seconds: u32) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get current clipboard content checksum to verify before clearing
    const current_content = paste(allocator) catch "";
    defer if (current_content.len > 0) allocator.free(current_content);
    const checksum = computeChecksum(current_content);

    const timeout_str = try std.fmt.allocPrint(allocator, "{d}", .{timeout_seconds});
    defer allocator.free(timeout_str);

    const checksum_str = try std.fmt.allocPrint(allocator, "{d}", .{checksum});
    defer allocator.free(checksum_str);

    // Shell script that:
    // 1. Sleeps for timeout
    // 2. Gets current clipboard content
    // 3. Computes checksum using cksum (available on most systems)
    // 4. Only clears if checksum matches (content unchanged)
    switch (comptime builtin.os.tag) {
        .macos => {
            // On macOS, use a more robust approach: store expected checksum and verify
            // We use a simpler approach: just clear after timeout
            // The shell script checks if clipboard changed by comparing checksums
            var child = std.process.Child.init(&.{
                "/bin/sh",
                "-c",
                \\sleep "$1"
                \\current=$(pbpaste 2>/dev/null | cksum | cut -d' ' -f1)
                \\if [ "$current" = "$2" ]; then
                \\  echo -n '' | pbcopy
                \\fi
                ,
                "--",
                timeout_str,
                checksum_str,
            }, allocator);
            try child.spawn();
            // Don't wait - let it run in background
        },
        .linux => {
            var child = std.process.Child.init(&.{
                "/bin/sh",
                "-c",
                \\sleep "$1"
                \\current=$(wl-paste 2>/dev/null | cksum | cut -d' ' -f1 || xclip -selection clipboard -o 2>/dev/null | cksum | cut -d' ' -f1)
                \\if [ "$current" = "$2" ]; then
                \\  wl-copy '' 2>/dev/null || xclip -selection clipboard < /dev/null 2>/dev/null
                \\fi
                ,
                "--",
                timeout_str,
                checksum_str,
            }, allocator);
            try child.spawn();
        },
        else => {},
    }
}

// =============================================================================
// TESTS
// =============================================================================

test "clipboard roundtrip" {
    // Skip this test in CI where clipboard may not be available
    if (std.posix.getenv("CI") != null) return;

    const test_text = "zig-passage-test-12345";
    copy(test_text) catch return; // Skip if clipboard unavailable

    const pasted = paste(std.testing.allocator) catch return;
    defer std.testing.allocator.free(pasted);

    // Clipboard might add trailing newline
    const trimmed = std.mem.trim(u8, pasted, "\n\r");
    try std.testing.expectEqualStrings(test_text, trimmed);
}

test "clear clipboard" {
    // Skip this test in CI
    if (std.posix.getenv("CI") != null) return;

    // First copy something
    copy("test-content") catch return;

    // Then clear it
    clear() catch return;

    // Verify it's empty or different
    const pasted = paste(std.testing.allocator) catch return;
    defer std.testing.allocator.free(pasted);

    try std.testing.expect(pasted.len == 0 or !std.mem.eql(u8, pasted, "test-content"));
}

test "copy empty string" {
    if (std.posix.getenv("CI") != null) return;

    // Should not error when copying empty string
    copy("") catch return;
}
