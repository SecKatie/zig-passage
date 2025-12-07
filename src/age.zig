const std = @import("std");
const fs = std.fs;

// =============================================================================
// AGE ENCRYPTION MODULE
// =============================================================================
//
// This module provides age encryption/decryption via FFI bindings to the
// Rust `age` crate. This replaces the previous shell-based implementation
// for better performance and reliability.
// =============================================================================

// FFI bindings to libage_ffi (Rust)
const c = struct {
    const AgeResult = enum(c_int) {
        Success = 0,
        InvalidInput = 1,
        EncryptionFailed = 2,
        DecryptionFailed = 3,
        KeygenFailed = 4,
        IoError = 5,
        InvalidRecipient = 6,
        InvalidIdentity = 7,
    };

    const AgeKeypair = extern struct {
        public_key: ?[*:0]u8,
        private_key: ?[*:0]u8,
    };

    extern fn age_decrypt_file(
        encrypted_path: [*:0]const u8,
        identity_path: [*:0]const u8,
        output: *?[*:0]u8,
        output_len: *usize,
    ) AgeResult;

    extern fn age_encrypt_to_file(
        plaintext: [*]const u8,
        plaintext_len: usize,
        output_path: [*:0]const u8,
        recipient: [*:0]const u8,
    ) AgeResult;

    extern fn age_generate_keypair(keypair: *AgeKeypair) AgeResult;

    extern fn age_free_string(s: ?[*:0]u8) void;
    extern fn age_free_keypair(keypair: *AgeKeypair) void;
};

pub const AgeError = error{
    DecryptionFailed,
    EncryptionFailed,
    KeygenFailed,
    InvalidInput,
    IoError,
    InvalidRecipient,
    InvalidIdentity,
};

/// Convert C AgeResult to Zig error
fn resultToError(result: c.AgeResult) AgeError!void {
    return switch (result) {
        .Success => {},
        .InvalidInput => AgeError.InvalidInput,
        .EncryptionFailed => AgeError.EncryptionFailed,
        .DecryptionFailed => AgeError.DecryptionFailed,
        .KeygenFailed => AgeError.KeygenFailed,
        .IoError => AgeError.IoError,
        .InvalidRecipient => AgeError.InvalidRecipient,
        .InvalidIdentity => AgeError.InvalidIdentity,
    };
}

/// Decrypt an age-encrypted file using the identity file
pub fn decrypt(allocator: std.mem.Allocator, encrypted_path: []const u8, identity_file: []const u8) ![]const u8 {
    // Convert paths to null-terminated strings
    const encrypted_path_z = try allocator.dupeZ(u8, encrypted_path);
    defer allocator.free(encrypted_path_z);

    const identity_file_z = try allocator.dupeZ(u8, identity_file);
    defer allocator.free(identity_file_z);

    var output: ?[*:0]u8 = null;
    var output_len: usize = 0;

    const result = c.age_decrypt_file(
        encrypted_path_z.ptr,
        identity_file_z.ptr,
        &output,
        &output_len,
    );

    try resultToError(result);

    if (output) |ptr| {
        // Copy the data to a Zig-managed slice
        const data = try allocator.dupe(u8, ptr[0..output_len]);
        // Free the Rust-allocated string
        c.age_free_string(ptr);
        return data;
    }

    return AgeError.DecryptionFailed;
}

/// Encrypt content to a file using recipients
pub fn encrypt(allocator: std.mem.Allocator, content: []const u8, output_path: []const u8, recipients: []const u8) !void {
    // Convert paths to null-terminated strings
    const output_path_z = try allocator.dupeZ(u8, output_path);
    defer allocator.free(output_path_z);

    const recipients_z = try allocator.dupeZ(u8, recipients);
    defer allocator.free(recipients_z);

    const result = c.age_encrypt_to_file(
        content.ptr,
        content.len,
        output_path_z.ptr,
        recipients_z.ptr,
    );

    try resultToError(result);
}

/// Generate a new age keypair
pub fn generateKeypair(allocator: std.mem.Allocator) !struct { public_key: []const u8, private_key: []const u8 } {
    var keypair: c.AgeKeypair = .{
        .public_key = null,
        .private_key = null,
    };

    const result = c.age_generate_keypair(&keypair);
    try resultToError(result);

    // Copy strings to Zig-managed memory
    const public_key = if (keypair.public_key) |pk| blk: {
        const len = std.mem.len(pk);
        break :blk try allocator.dupe(u8, pk[0..len]);
    } else return AgeError.KeygenFailed;

    const private_key = if (keypair.private_key) |sk| blk: {
        const len = std.mem.len(sk);
        break :blk try allocator.dupe(u8, sk[0..len]);
    } else {
        allocator.free(public_key);
        return AgeError.KeygenFailed;
    };

    // Free Rust-allocated memory
    c.age_free_keypair(&keypair);

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

    // Write recipients file with public key
    const recipients_path = tmp_dir ++ "/recipients";
    const rec_file = try fs.createFileAbsolute(recipients_path, .{});
    try rec_file.writeAll(keypair.public_key);
    try rec_file.writeAll("\n");
    rec_file.close();

    // Test content
    const original = "Hello, this is a secret message!";
    const encrypted_path = tmp_dir ++ "/encrypted.age";

    // Encrypt
    try encrypt(allocator, original, encrypted_path, recipients_path);

    // Verify encrypted file exists
    try fs.accessAbsolute(encrypted_path, .{});

    // Decrypt
    const decrypted = try decrypt(allocator, encrypted_path, identity_path);
    defer allocator.free(decrypted);

    // Verify content matches
    try std.testing.expectEqualStrings(original, decrypted);
}

test "encrypt with direct recipient key" {
    const allocator = std.testing.allocator;

    // Create temp directory for test
    const tmp_dir = "/tmp/passage-age-test-direct";
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

    // Test content
    const original = "Direct recipient encryption test!";
    const encrypted_path = tmp_dir ++ "/encrypted.age";

    // Encrypt using direct public key (not a file)
    try encrypt(allocator, original, encrypted_path, keypair.public_key);

    // Decrypt
    const decrypted = try decrypt(allocator, encrypted_path, identity_path);
    defer allocator.free(decrypted);

    // Verify content matches
    try std.testing.expectEqualStrings(original, decrypted);
}
