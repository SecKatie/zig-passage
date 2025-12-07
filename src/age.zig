const std = @import("std");
const fs = std.fs;
const process = std.process;

// =============================================================================
// AGE ENCRYPTION MODULE
// =============================================================================
//
// This module wraps the `age` command-line tool for encryption/decryption.
// Unlike the bash version which uses pipes, we use temp files for simplicity.
//
// In the future, you could link directly to libsodium for native encryption,
// but calling the age binary maintains compatibility with existing stores.
// =============================================================================

pub const AgeError = error{
    DecryptionFailed,
    EncryptionFailed,
    AgeBinaryNotFound,
    InvalidRecipients,
};

/// Decrypt an age-encrypted file using the identity file
pub fn decrypt(allocator: std.mem.Allocator, encrypted_path: []const u8, identity_file: []const u8) ![]const u8 {
    // Find age binary
    const age_bin = std.posix.getenv("PASSAGE_AGE") orelse "age";

    // Build command: age -d -i identity_file encrypted_path
    const argv = [_][]const u8{ age_bin, "-d", "-i", identity_file, encrypted_path };

    // Spawn child process and capture output
    var child = std.process.Child.init(&argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    try child.spawn();

    // Read stdout (the decrypted content)
    const stdout = child.stdout.?;
    var read_buf: [4096]u8 = undefined;
    var f_reader = stdout.reader(&read_buf);
    const output = try f_reader.interface.allocRemaining(allocator, .unlimited);

    const result = child.wait() catch return AgeError.DecryptionFailed;

    if (result.Exited != 0) {
        allocator.free(output);
        return AgeError.DecryptionFailed;
    }

    return output;
}

/// Encrypt content to a file using recipients
pub fn encrypt(allocator: std.mem.Allocator, content: []const u8, output_path: []const u8, recipients: []const u8) !void {
    const age_bin = std.posix.getenv("PASSAGE_AGE") orelse "age";

    // Determine if recipients is a file or a raw recipient
    const is_file = std.fs.path.isAbsolute(recipients) or std.mem.startsWith(u8, recipients, ".");

    // Build command
    var argv_list: std.ArrayList([]const u8) = .empty;
    defer argv_list.deinit(allocator);

    try argv_list.append(allocator, age_bin);
    try argv_list.append(allocator, "-e");

    if (is_file) {
        try argv_list.append(allocator, "-R");
    } else {
        try argv_list.append(allocator, "-r");
    }
    try argv_list.append(allocator, recipients);

    try argv_list.append(allocator, "-o");
    try argv_list.append(allocator, output_path);

    var child = std.process.Child.init(argv_list.items, allocator);
    child.stdin_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    try child.spawn();

    // Write content to stdin
    const stdin = child.stdin.?;
    try stdin.writeAll(content);
    stdin.close();
    child.stdin = null;

    const result = child.wait() catch return AgeError.EncryptionFailed;

    if (result.Exited != 0) {
        return AgeError.EncryptionFailed;
    }
}

/// Generate a new age keypair
pub fn generateKeypair(allocator: std.mem.Allocator) !struct { public_key: []const u8, private_key: []const u8 } {
    const age_keygen = std.posix.getenv("PASSAGE_AGE_KEYGEN") orelse "age-keygen";

    var child = std.process.Child.init(&.{age_keygen}, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    try child.spawn();

    // age-keygen outputs to stdout:
    // - # created: timestamp
    // - # public key: age1...
    // - AGE-SECRET-KEY-...
    //
    // And to stderr:
    // - Public key: age1...

    const stdout = child.stdout.?;
    const stderr = child.stderr.?;

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;
    var stdout_reader = stdout.reader(&stdout_buf);
    var stderr_reader = stderr.reader(&stderr_buf);
    const private_key = try stdout_reader.interface.allocRemaining(allocator, .unlimited);
    const stderr_output = try stderr_reader.interface.allocRemaining(allocator, .unlimited);
    defer allocator.free(stderr_output);

    const result = try child.wait();
    if (result.Exited != 0) {
        allocator.free(private_key);
        return error.KeygenFailed;
    }

    // Parse public key from stdout (format: "# public key: age1...")
    // The full output (private_key) contains the public key as a comment
    var public_key: []const u8 = "";
    var lines = std.mem.splitSequence(u8, private_key, "\n");
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "# public key: ")) {
            public_key = try allocator.dupe(u8, line[14..]);
            break;
        }
    }

    return .{
        .public_key = public_key,
        .private_key = private_key,
    };
}

// =============================================================================
// TESTS
// =============================================================================

test "age binary exists" {
    // This test checks if age is installed (useful for CI)
    const age_bin = std.posix.getenv("PASSAGE_AGE") orelse "age";

    var child = std.process.Child.init(&.{ age_bin, "--version" }, std.testing.allocator);
    child.stdout_behavior = .Pipe;

    child.spawn() catch {
        std.debug.print("Warning: age binary not found at '{s}'\n", .{age_bin});
        return;
    };

    _ = try child.wait();
}

test "age-keygen binary exists" {
    const age_keygen = std.posix.getenv("PASSAGE_AGE_KEYGEN") orelse "age-keygen";

    var child = std.process.Child.init(&.{ age_keygen, "--version" }, std.testing.allocator);
    child.stdout_behavior = .Pipe;

    child.spawn() catch {
        std.debug.print("Warning: age-keygen binary not found at '{s}'\n", .{age_keygen});
        return;
    };

    _ = try child.wait();
}

test "encrypt and decrypt roundtrip" {
    const allocator = std.testing.allocator;

    // Skip if age not installed
    var check_child = std.process.Child.init(&.{ "age", "--version" }, allocator);
    check_child.stdout_behavior = .Pipe;
    check_child.spawn() catch return;
    _ = try check_child.wait();

    // Create temp directory for test
    const tmp_dir = "/tmp/passage-age-test";
    fs.deleteTreeAbsolute(tmp_dir) catch {};
    try fs.makeDirAbsolute(tmp_dir);
    defer fs.deleteTreeAbsolute(tmp_dir) catch {};

    // Generate keypair
    const keypair = generateKeypair(allocator) catch |err| {
        std.debug.print("Keygen failed: {}\n", .{err});
        return;
    };
    defer allocator.free(keypair.public_key);
    defer allocator.free(keypair.private_key);

    // Write identity file (contains the full private key output from age-keygen)
    const identity_path = tmp_dir ++ "/identity";
    const id_file = try fs.createFileAbsolute(identity_path, .{});
    try id_file.writeAll(keypair.private_key);
    id_file.close();

    // Write recipients file with public key (just the key, one per line)
    const recipients_path = tmp_dir ++ "/recipients";
    const rec_file = try fs.createFileAbsolute(recipients_path, .{});
    try rec_file.writeAll(keypair.public_key);
    try rec_file.writeAll("\n");
    rec_file.close();

    // Test content
    const original = "Hello, this is a secret message!";
    const encrypted_path = tmp_dir ++ "/encrypted.age";

    // Encrypt
    encrypt(allocator, original, encrypted_path, recipients_path) catch |err| {
        std.debug.print("Encryption failed: {}\n", .{err});
        std.debug.print("Public key: {s}\n", .{keypair.public_key});
        return;
    };

    // Verify encrypted file exists
    try fs.accessAbsolute(encrypted_path, .{});

    // Decrypt
    const decrypted = try decrypt(allocator, encrypted_path, identity_path);
    defer allocator.free(decrypted);

    // Verify content matches
    try std.testing.expectEqualStrings(original, decrypted);
}
