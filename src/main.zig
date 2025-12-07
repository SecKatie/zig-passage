const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const process = std.process;

// In Zig, we import other source files as modules
const Store = @import("store.zig").Store;
const cli = @import("cli.zig");

// =============================================================================
// ZIG BASICS FOR HIGH-LEVEL LANGUAGE DEVELOPERS
// =============================================================================
//
// 1. NO GARBAGE COLLECTION
//    Unlike Python/JS, you manage memory manually. But Zig makes this safe
//    with "allocators" - objects that handle allocation/deallocation.
//
// 2. ERROR HANDLING
//    Instead of try/catch, Zig uses error unions: `fn foo() !i32`
//    The `!` means "this can fail". Use `try` to propagate errors up.
//
// 3. OPTIONALS
//    Instead of null/None, Zig has `?T` (optional type).
//    `if (maybe_value) |value|` unwraps it safely.
//
// 4. SLICES
//    `[]u8` is a "slice" - a pointer + length. Like Python's list[start:end]
//    but as a first-class type.
// =============================================================================

pub fn main() !void {
    // Get an allocator. GeneralPurposeAllocator is a good default.
    // In Python, you never think about this - memory just "works".
    // In Zig, you explicitly request memory and must free it.
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit(); // `defer` runs when function exits (like Python's `finally`)

    const allocator = gpa.allocator();

    // Parse command line arguments
    const args = try process.argsAlloc(allocator);
    defer process.argsFree(allocator, args); // Always pair alloc with free!

    // Handle the command
    cli.run(allocator, args) catch |err| {
        // Error handling: we catch and display user-friendly messages
        var stderr_buf: [1024]u8 = undefined;
        var stderr_writer = std.fs.File.stderr().writer(&stderr_buf);
        const stderr = &stderr_writer.interface;
        switch (err) {
            error.PasswordNotFound => try stderr.print("Error: password not found\n", .{}),
            error.StoreNotInitialized => try stderr.print("Error: password store not initialized\n", .{}),
            error.DecryptionFailed => try stderr.print("Error: decryption failed - check your identity file\n", .{}),
            else => try stderr.print("Error: {}\n", .{err}),
        }
        try stderr.flush();
        process.exit(1);
    };
}

// =============================================================================
// TESTS - Built into the language!
// Run with: zig build test
// =============================================================================

// Reference all test modules so their tests are included
test {
    // This ensures tests from all modules are discovered and run
    _ = @import("cli.zig");
    _ = @import("store.zig");
    _ = @import("age.zig");
    _ = @import("clipboard.zig");
}

test "basic sanity check" {
    // Tests are first-class in Zig. No external test framework needed!
    const x: i32 = 1 + 1;
    try std.testing.expectEqual(@as(i32, 2), x);
}
