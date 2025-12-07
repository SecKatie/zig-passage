const std = @import("std");
const fs = std.fs;

// Import the new age-ffi bindings
const age_lib = @import("age");

// =============================================================================
// AGE ENCRYPTION MODULE - Compatibility Wrapper
// =============================================================================
//
// This module provides backward-compatible wrappers around the new age-ffi
// Zig bindings, maintaining the same API that the rest of the codebase uses.
// =============================================================================

// Re-export error types
pub const AgeError = age_lib.AgeError;

/// Decrypt an age-encrypted file using the identity file
/// Returns allocated memory that the caller must free
pub fn decrypt(allocator: std.mem.Allocator, encrypted_path: []const u8, identity_file: []const u8) ![]const u8 {
    // Convert to null-terminated strings
    const encrypted_path_z = try allocator.dupeZ(u8, encrypted_path);
    defer allocator.free(encrypted_path_z);

    const identity_file_z = try allocator.dupeZ(u8, identity_file);
    defer allocator.free(identity_file_z);

    // Use the new API
    var buffer = try age_lib.decryptFile(encrypted_path_z, identity_file_z);
    defer buffer.deinit();

    // Convert to owned slice (the caller will free this)
    return try allocator.dupe(u8, buffer.toSlice());
}

/// Encrypt content to a file using recipients
/// The recipients parameter can be either:
/// - A path to a file containing recipient public keys (one per line)
/// - A direct recipient public key string
pub fn encrypt(allocator: std.mem.Allocator, content: []const u8, output_path: []const u8, recipients: []const u8) !void {
    const output_path_z = try allocator.dupeZ(u8, output_path);
    defer allocator.free(output_path_z);

    // Check if recipients is a file path or a direct key
    // If it starts with "age1" it's likely a direct key, otherwise try to read it as a file
    const is_direct_key = std.mem.startsWith(u8, recipients, "age1");

    if (is_direct_key) {
        // Direct recipient key
        const recipients_z = try allocator.dupeZ(u8, recipients);
        defer allocator.free(recipients_z);

        try age_lib.encryptToFile(content, recipients_z, output_path_z);
    } else {
        // Assume it's a file path, read the first recipient from it
        const file = try fs.openFileAbsolute(recipients, .{});
        defer file.close();

        const file_content = try file.readToEndAlloc(allocator, 1024 * 1024); // 1MB max
        defer allocator.free(file_content);

        // Get the first line (first recipient)
        var lines = std.mem.tokenizeScalar(u8, file_content, '\n');
        const first_line = lines.next() orelse return error.NoRecipients;

        // Trim whitespace
        const recipient = std.mem.trim(u8, first_line, " \t\r");

        const recipient_z = try allocator.dupeZ(u8, recipient);
        defer allocator.free(recipient_z);

        try age_lib.encryptToFile(content, recipient_z, output_path_z);
    }
}

/// Generate a new age keypair
pub fn generateKeypair(allocator: std.mem.Allocator) !struct { public_key: []const u8, private_key: []const u8 } {
    var keypair = try age_lib.generateKeypair();
    defer keypair.deinit();

    // Copy to allocator-owned memory
    const public_key = try allocator.dupe(u8, keypair.getPublicKey());
    const private_key = try allocator.dupe(u8, keypair.getPrivateKey());

    return .{
        .public_key = public_key,
        .private_key = private_key,
    };
}

// =============================================================================
// TESTS
// =============================================================================

test "generate keypair" {
    const allocator = std.testing.allocator;

    const keypair = try generateKeypair(allocator);
    defer allocator.free(keypair.public_key);
    defer allocator.free(keypair.private_key);

    // Public key should start with "age1"
    try std.testing.expect(std.mem.startsWith(u8, keypair.public_key, "age1"));

    // Private key should start with "AGE-SECRET-KEY-"
    try std.testing.expect(std.mem.startsWith(u8, keypair.private_key, "AGE-SECRET-KEY-"));
}

test "encrypt and decrypt roundtrip" {
    const allocator = std.testing.allocator;

    // Create temp directory for test
    const tmp_dir = "/tmp/passage-age-test";
    fs.deleteTreeAbsolute(tmp_dir) catch {};
    try fs.makeDirAbsolute(tmp_dir);
    defer fs.deleteTreeAbsolute(tmp_dir) catch {};

    // Generate keypair
    const keypair = try generateKeypair(allocator);
    defer allocator.free(keypair.public_key);
    defer allocator.free(keypair.private_key);

    // Write identity file (private key only for age library)
    const identity_path = tmp_dir ++ "/identity";
    const id_file = try fs.createFileAbsolute(identity_path, .{});
    try id_file.writeAll(keypair.private_key);
    id_file.close();

    // Test content
    const original = "Hello, this is a secret message!";
    const encrypted_path = tmp_dir ++ "/encrypted.age";

    // Encrypt using direct public key
    try encrypt(allocator, original, encrypted_path, keypair.public_key);

    // Verify encrypted file exists
    try fs.accessAbsolute(encrypted_path, .{});

    // Decrypt
    const decrypted = try decrypt(allocator, encrypted_path, identity_path);
    defer allocator.free(decrypted);

    // Verify content matches
    try std.testing.expectEqualStrings(original, decrypted);
}

test "encrypt with recipients file" {
    const allocator = std.testing.allocator;

    // Create temp directory for test
    const tmp_dir = "/tmp/passage-age-test-file";
    fs.deleteTreeAbsolute(tmp_dir) catch {};
    try fs.makeDirAbsolute(tmp_dir);
    defer fs.deleteTreeAbsolute(tmp_dir) catch {};

    // Generate keypair
    const keypair = try generateKeypair(allocator);
    defer allocator.free(keypair.public_key);
    defer allocator.free(keypair.private_key);

    // Write identity file
    const identity_path = tmp_dir ++ "/identity";
    const id_file = try fs.createFileAbsolute(identity_path, .{});
    try id_file.writeAll(keypair.private_key);
    id_file.close();

    // Write recipients file with public key
    const recipients_path = tmp_dir ++ "/recipients";
    const rec_file = try fs.createFileAbsolute(recipients_path, .{});
    try rec_file.writeAll(keypair.public_key);
    try rec_file.writeAll("\n");
    rec_file.close();

    // Test content
    const original = "Recipients file encryption test!";
    const encrypted_path = tmp_dir ++ "/encrypted.age";

    // Encrypt using recipients file path
    try encrypt(allocator, original, encrypted_path, recipients_path);

    // Decrypt
    const decrypted = try decrypt(allocator, encrypted_path, identity_path);
    defer allocator.free(decrypted);

    // Verify content matches
    try std.testing.expectEqualStrings(original, decrypted);
}
