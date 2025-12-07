const std = @import("std");
const builtin = @import("builtin");
const fs = std.fs;
const mem = std.mem;
const posix = std.posix;

const age = @import("age.zig");
const cli = @import("cli.zig");
const clipboard = @import("clipboard.zig");
const utils = @import("utils.zig");
const zxing = @import("zxing");

const CLIP_TIME: u32 = 45; // seconds to clear clipboard

// =============================================================================
// PASSWORD STORE
// =============================================================================
//
// This is the core data structure representing the password store.
// It mirrors the bash version's directory structure:
//
//   ~/.passage/
//     identities     <- age identity file (private key)
//     store/         <- encrypted passwords
//       github.com.age
//       email/
//         personal.age
//         work.age
// =============================================================================

pub const Store = struct {
    allocator: std.mem.Allocator,
    store_dir: []const u8,
    identities_file: []const u8,

    const Self = @This();

    // In Zig, errors are defined as enum-like sets
    // Functions declare which errors they can return with `!`
    pub const Error = error{
        StoreNotInitialized,
        PasswordNotFound,
        PasswordExists,
        DecryptionFailed,
        EncryptionFailed,
        NoRecipientsFound,
        InvalidPath,
        SneakyPath,
        QrCodeFailed,
    };

    /// Opens an existing password store or prepares for initialization
    pub fn open(allocator: std.mem.Allocator) !Self {
        const home = std.posix.getenv("HOME") orelse return error.HomeNotFound;

        // Always allocate owned copies so deinit can unconditionally free
        const store_dir = if (std.posix.getenv("PASSAGE_DIR")) |env|
            try allocator.dupe(u8, std.mem.sliceTo(env, 0))
        else
            try std.fmt.allocPrint(allocator, "{s}/.passage/store", .{home});

        const identities_file = if (std.posix.getenv("PASSAGE_IDENTITIES_FILE")) |env|
            try allocator.dupe(u8, std.mem.sliceTo(env, 0))
        else
            try std.fmt.allocPrint(allocator, "{s}/.passage/identities", .{home});

        return Self{
            .allocator = allocator,
            .store_dir = store_dir,
            .identities_file = identities_file,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.store_dir);
        self.allocator.free(self.identities_file);
    }

    /// List passwords in the store
    pub fn list(self: *Self, stdout: std.fs.File, subfolder: ?[]const u8) !void {
        const path = if (subfolder) |sub|
            try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.store_dir, sub })
        else
            self.store_dir;
        defer if (subfolder != null) self.allocator.free(path);

        // Check if store exists
        var dir = fs.openDirAbsolute(path, .{ .iterate = true }) catch |err| {
            if (err == error.FileNotFound) {
                return Error.StoreNotInitialized;
            }
            return err;
        };
        defer dir.close();

        // Print header (like tree does)
        const display_name = subfolder orelse "Password Store";
        try stdout.writeAll(display_name);
        try stdout.writeAll("\n");

        // Recursively list entries
        try self.listRecursive(stdout, dir, 0);
    }

    fn listRecursive(self: *Self, stdout: std.fs.File, dir: fs.Dir, depth: usize) !void {
        var it = dir.iterate();
        var entries: std.ArrayList(fs.Dir.Entry) = .empty;
        defer entries.deinit(self.allocator);

        // Collect and sort entries
        while (try it.next()) |entry| {
            // Skip hidden files and non-.age files
            if (entry.name[0] == '.') continue;
            if (entry.kind == .file and !mem.endsWith(u8, entry.name, ".age")) continue;

            try entries.append(self.allocator, entry);
        }

        // Sort by name
        mem.sort(fs.Dir.Entry, entries.items, {}, struct {
            fn lessThan(_: void, a: fs.Dir.Entry, b: fs.Dir.Entry) bool {
                return mem.lessThan(u8, a.name, b.name);
            }
        }.lessThan);

        for (entries.items, 0..) |entry, idx| {
            const is_last = idx == entries.items.len - 1;
            const prefix = if (is_last) "\u{2514}\u{2500}\u{2500} " else "\u{251C}\u{2500}\u{2500} ";

            // Indent based on depth
            for (0..depth) |_| {
                try stdout.writeAll("\u{2502}   ");
            }
            try stdout.writeAll(prefix);

            // Print name (strip .age extension for files)
            const display_name = if (entry.kind == .file)
                entry.name[0 .. entry.name.len - 4]
            else
                entry.name;

            try stdout.writeAll(display_name);
            try stdout.writeAll("\n");

            // Recurse into directories
            if (entry.kind == .directory) {
                var subdir = try dir.openDir(entry.name, .{ .iterate = true });
                defer subdir.close();
                try self.listRecursive(stdout, subdir, depth + 1);
            }
        }
    }

    /// Show/decrypt a password
    pub fn show(self: *Self, allocator: std.mem.Allocator, name: []const u8) ![]const u8 {
        try utils.checkSneakyPaths(name);

        const path = try std.fmt.allocPrint(allocator, "{s}/{s}.age", .{ self.store_dir, name });
        defer allocator.free(path);

        // Check if file exists
        fs.accessAbsolute(path, .{}) catch {
            return Error.PasswordNotFound;
        };

        // Decrypt using age
        return age.decrypt(allocator, path, self.identities_file) catch {
            return Error.DecryptionFailed;
        };
    }

    /// Display password as QR code using native zxing-cpp bindings
    pub fn showQrCode(self: *Self, allocator: std.mem.Allocator, name: []const u8, line: ?u32) !void {
        const content = try self.show(allocator, name);
        defer utils.secureFree(allocator, @constCast(content));

        // Get the specific line (default to first line)
        const target_line = line orelse 1;
        var lines = mem.splitSequence(u8, content, "\n");
        var current: u32 = 1;
        var text: []const u8 = content;

        while (lines.next()) |l| {
            if (current == target_line) {
                text = l;
                break;
            }
            current += 1;
        }

        if (text.len == 0) {
            return Error.PasswordNotFound;
        }

        // Create QR code using native zxing library
        var creator = zxing.create(.qr_code) catch return Error.QrCodeFailed;
        defer creator.deinit();

        var barcode = creator.fromText(text) catch return Error.QrCodeFailed;
        defer barcode.deinit();

        // Get image and convert to UTF-8 for terminal
        var writer = zxing.write() catch return Error.QrCodeFailed;
        defer writer.deinit();
        _ = writer.scale(1).withQuietZones(true);

        var image = barcode.toImage(&writer.options) catch return Error.QrCodeFailed;
        defer image.deinit();

        const width: usize = @intCast(image.width());
        const height: usize = @intCast(image.height());
        const data = image.data();

        const stdout_file = std.fs.File.stdout();

        // Convert to UTF-8 using Unicode block characters
        // Process two rows at a time using half-block characters
        var y: usize = 0;
        while (y < height) : (y += 2) {
            var x: usize = 0;
            while (x < width) : (x += 1) {
                const top = if (y < height) data[y * width + x] < 128 else false;
                const bottom = if (y + 1 < height) data[(y + 1) * width + x] < 128 else false;

                const char: []const u8 = if (top and bottom)
                    "\u{2588}" // Full block (both dark)
                else if (top)
                    "\u{2580}" // Upper half block
                else if (bottom)
                    "\u{2584}" // Lower half block
                else
                    " "; // Space (both light)

                stdout_file.writeAll(char) catch {};
            }
            stdout_file.writeAll("\n") catch {};
        }
    }

    /// Copy password to clipboard with timeout clearing
    pub fn copyToClipboard(self: *Self, allocator: std.mem.Allocator, name: []const u8, line: ?u32) !void {
        const content = try self.show(allocator, name);
        defer utils.secureFree(allocator, @constCast(content));

        // Get the specific line (default to first line)
        const target_line = line orelse 1;
        var lines = mem.splitSequence(u8, content, "\n");
        var current: u32 = 1;
        var text: ?[]const u8 = null;

        while (lines.next()) |l| {
            if (current == target_line) {
                text = l;
                break;
            }
            current += 1;
        }

        // If we didn't find the target line, use first line
        const final_text = text orelse (if (mem.indexOf(u8, content, "\n")) |idx| content[0..idx] else content);

        try clipboard.copy(final_text);
        clipboard.clearAfterTimeout(CLIP_TIME) catch {};

        var stdout_buf: [256]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
        const stdout = &stdout_writer.interface;
        try stdout.print("Copied {s} to clipboard. Will clear in {d} seconds.\n", .{ name, CLIP_TIME });
        try stdout.flush();
    }

    /// Insert a new password
    pub fn insert(self: *Self, opts: cli.Command.InsertOptions) !void {
        try utils.checkSneakyPaths(opts.name);

        const path = try std.fmt.allocPrint(self.allocator, "{s}/{s}.age", .{ self.store_dir, opts.name });
        defer self.allocator.free(path);

        // Check if exists (only error if file exists and force is not set)
        if (!opts.force) {
            if (fs.accessAbsolute(path, .{})) |_| {
                return Error.PasswordExists;
            } else |err| {
                if (err != error.FileNotFound) return err;
                // FileNotFound is fine - we're creating a new password
            }
        }

        // Read password from stdin
        const stdin = std.fs.File.stdin();
        const stdout = std.fs.File.stdout();

        var password_buf: [4096]u8 = undefined;
        var password: []const u8 = undefined;

        if (opts.multiline) {
            var msg_buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "Enter contents of {s} and press Ctrl+D when finished:\n\n", .{opts.name}) catch "Enter contents:\n\n";
            try stdout.writeAll(msg);
            const bytes_read = try stdin.readAll(&password_buf);
            password = password_buf[0..bytes_read];
        } else {
            var msg_buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "Enter password for {s}: ", .{opts.name}) catch "Enter password: ";
            try stdout.writeAll(msg);

            // Disable echo for password entry (unless -e flag)
            if (!opts.echo) {
                disableEcho();
            }
            defer if (!opts.echo) enableEcho();

            var read_buf: [4096]u8 = undefined;
            var f_reader = stdin.reader(&read_buf);
            password = f_reader.interface.takeDelimiterExclusive('\n') catch |err| {
                if (err == error.EndOfStream) {
                    return; // User cancelled
                }
                return err;
            };

            if (!opts.echo) {
                try stdout.writeAll("\n");
                // Confirm the password
                const msg2 = std.fmt.bufPrint(&msg_buf, "Retype password for {s}: ", .{opts.name}) catch "Retype password: ";
                try stdout.writeAll(msg2);

                // Need a new reader for second password
                var read_buf2: [4096]u8 = undefined;
                var f_reader2 = stdin.reader(&read_buf2);
                const confirm = f_reader2.interface.takeDelimiterExclusive('\n') catch return;

                if (!mem.eql(u8, password, confirm)) {
                    try stdout.writeAll("\nError: the entered passwords do not match.\n");
                    return error.PasswordMismatch;
                }
            }
        }

        // Create parent directories if needed
        if (std.fs.path.dirname(path)) |parent| {
            fs.makeDirAbsolute(parent) catch |err| {
                if (err != error.PathAlreadyExists) return err;
            };
        }

        // Encrypt and save
        const recipients = try self.getRecipients(opts.name);
        defer self.allocator.free(recipients);
        try age.encrypt(self.allocator, password, path, recipients);

        try stdout.writeAll("\n");
        try self.gitCommit("Add password for {s}", .{opts.name});
    }

    // Saved terminal state for restoration
    var saved_termios: ?std.posix.termios = null;

    /// Disable terminal echo for password entry
    /// Saves original terminal state so it can be restored
    fn disableEcho() void {
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
    fn enableEcho() void {
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

    /// Generate a new password
    pub fn generate(self: *Self, allocator: std.mem.Allocator, opts: cli.Command.GenerateOptions) !void {
        try utils.checkSneakyPaths(opts.name);

        var stdout_buf: [1024]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
        const stdout = &stdout_writer.interface;

        // Generate random password
        var password_buf: [256]u8 = undefined;
        const length = @min(opts.length, password_buf.len);

        const charset = if (opts.no_symbols)
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        else
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";

        // Use crypto-secure random with rejection sampling to avoid modulo bias
        // Modulo bias occurs because 256 doesn't divide evenly by charset.len
        // Calculate the largest multiple of charset.len that fits in 0-255
        const charset_len: u9 = @intCast(charset.len);
        const remainder: u9 = 256 % charset_len;
        // If remainder is 0, all values are unbiased; otherwise reject values >= (256 - remainder)
        const max_valid: u8 = if (remainder == 0) 255 else @intCast(256 - remainder - 1);

        for (password_buf[0..length]) |*byte| {
            // Rejection sampling: discard values that would cause bias
            while (true) {
                var rand: [1]u8 = undefined;
                std.crypto.random.bytes(&rand);
                if (rand[0] <= max_valid) {
                    byte.* = charset[rand[0] % @as(u8, @intCast(charset.len))];
                    break;
                }
                // Value would cause bias, try again (very rare, ~3% for 62 chars, ~0.4% for 95 chars)
            }
        }
        const password = password_buf[0..length];

        const path = try std.fmt.allocPrint(allocator, "{s}/{s}.age", .{ self.store_dir, opts.name });
        defer allocator.free(path);

        // Check if exists (unless force or in_place)
        if (!opts.force and !opts.in_place) {
            fs.accessAbsolute(path, .{}) catch |err| {
                if (err != error.FileNotFound) return err;
            };
        }

        // For in_place, read existing content and replace first line
        var content: []const u8 = password;
        if (opts.in_place) {
            const existing = self.show(allocator, opts.name) catch password;
            defer if (existing.ptr != password.ptr) utils.secureFree(allocator, @constCast(existing));

            if (mem.indexOf(u8, existing, "\n")) |newline_idx| {
                // Replace first line, keep the rest
                const rest = existing[newline_idx..];
                const new_content = try std.fmt.allocPrint(allocator, "{s}{s}", .{ password, rest });
                content = new_content;
            }
        }

        // Create parent directories
        if (std.fs.path.dirname(path)) |parent| {
            fs.makeDirAbsolute(parent) catch |err| {
                if (err != error.PathAlreadyExists) return err;
            };
        }

        // Encrypt and save
        const recipients = try self.getRecipients(opts.name);
        defer self.allocator.free(recipients);
        try age.encrypt(allocator, content, path, recipients);

        if (opts.clip) {
            try clipboard.copy(password);
            clipboard.clearAfterTimeout(CLIP_TIME) catch {};
            try stdout.print("Generated password for {s} and copied to clipboard. Will clear in {d} seconds.\n", .{ opts.name, CLIP_TIME });
        } else {
            try stdout.print("Generated password for {s}:\n{s}\n", .{ opts.name, password });
        }

        try self.gitCommit("Generate password for {s}", .{opts.name});
    }

    /// Edit a password in the user's editor
    pub fn edit(self: *Self, allocator: std.mem.Allocator, name: []const u8) !void {
        try utils.checkSneakyPaths(name);

        const path = try std.fmt.allocPrint(allocator, "{s}/{s}.age", .{ self.store_dir, name });
        defer allocator.free(path);

        // Get editor
        const editor = std.posix.getenv("EDITOR") orelse std.posix.getenv("VISUAL") orelse "vi";

        // Create secure temp file with unpredictable name
        const secure_tmpdir = utils.getSecureTmpDir();

        // Generate random suffix for unpredictable filename (prevents symlink attacks)
        var rand_suffix: [16]u8 = undefined;
        std.crypto.random.bytes(&rand_suffix);
        // Use {x} format specifier to convert bytes to lowercase hex
        const tmp_path = try std.fmt.allocPrint(allocator, "{s}/passage-{x}.txt", .{
            secure_tmpdir,
            rand_suffix,
        });
        defer allocator.free(tmp_path);

        // Check if file exists (new or edit)
        const is_new = fs.accessAbsolute(path, .{}) == error.FileNotFound;
        var action: []const u8 = "Add";

        // If exists, decrypt to temp file
        if (!is_new) {
            action = "Edit";
            const content = try self.show(allocator, name);
            defer utils.secureFree(allocator, @constCast(content));

            // Create with restrictive permissions (owner read/write only)
            const tmp_file = try fs.createFileAbsolute(tmp_path, .{ .mode = 0o600 });
            defer tmp_file.close();
            try tmp_file.writeAll(content);
        } else {
            // Create empty temp file for new password with restrictive permissions
            const tmp_file = try fs.createFileAbsolute(tmp_path, .{ .mode = 0o600 });
            tmp_file.close();
        }

        // Ensure temp file is cleaned up
        defer fs.deleteFileAbsolute(tmp_path) catch {};

        // Launch editor
        var editor_child = std.process.Child.init(&.{ editor, tmp_path }, allocator);
        editor_child.stdin_behavior = .Inherit;
        editor_child.stdout_behavior = .Inherit;
        editor_child.stderr_behavior = .Inherit;

        try editor_child.spawn();
        const result = try editor_child.wait();

        if (result.Exited != 0) {
            return error.EditorFailed;
        }

        // Read edited content
        const tmp_file = fs.openFileAbsolute(tmp_path, .{}) catch {
            // User deleted the file - abort
            const stdout = std.fs.File.stdout();
            stdout.writeAll("New password not saved.\n") catch {};
            return;
        };
        defer tmp_file.close();

        const stat = try tmp_file.stat();
        if (stat.size == 0) {
            const stdout = std.fs.File.stdout();
            stdout.writeAll("Password unchanged (empty file).\n") catch {};
            return;
        }

        const new_content = try allocator.alloc(u8, stat.size);
        defer utils.secureFree(allocator, new_content);
        const bytes_read = try tmp_file.readAll(new_content);
        const content = new_content[0..bytes_read];

        // Check if content actually changed (for existing files)
        if (!is_new) {
            const old_content = self.show(allocator, name) catch "";
            defer if (old_content.len > 0) utils.secureFree(allocator, @constCast(old_content));

            if (mem.eql(u8, content, old_content)) {
                const stdout = std.fs.File.stdout();
                stdout.writeAll("Password unchanged.\n") catch {};
                return;
            }
        }

        // Create parent directories if needed (for new files)
        if (std.fs.path.dirname(path)) |parent| {
            fs.makeDirAbsolute(parent) catch |err| {
                if (err != error.PathAlreadyExists) return err;
            };
        }

        // Encrypt and save
        const recipients = try self.getRecipients(name);
        defer self.allocator.free(recipients);
        try age.encrypt(allocator, content, path, recipients);

        try self.gitCommit("{s} password for {s} using {s}", .{ action, name, editor });
    }

    /// Delete a password
    pub fn delete(self: *Self, opts: cli.Command.DeleteOptions) !void {
        try utils.checkSneakyPaths(opts.name);

        var stdout_buf: [1024]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
        const stdout = &stdout_writer.interface;
        const path = try std.fmt.allocPrint(self.allocator, "{s}/{s}.age", .{ self.store_dir, opts.name });
        defer self.allocator.free(path);

        if (!opts.force) {
            try stdout.print("Are you sure you want to delete {s}? [y/N] ", .{opts.name});
            try stdout.flush();
            const stdin = std.fs.File.stdin();
            var read_buf: [64]u8 = undefined;
            var f_reader = stdin.reader(&read_buf);
            const response = f_reader.interface.takeDelimiterExclusive('\n') catch "";
            if (response.len == 0 or (response[0] != 'y' and response[0] != 'Y')) {
                return;
            }
        }

        if (opts.recursive) {
            const dir_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.store_dir, opts.name });
            defer self.allocator.free(dir_path);

            fs.deleteTreeAbsolute(dir_path) catch |err| {
                if (err == error.FileNotFound) return Error.PasswordNotFound;
                return err;
            };
        } else {
            fs.deleteFileAbsolute(path) catch |err| {
                if (err == error.FileNotFound) return Error.PasswordNotFound;
                return err;
            };
        }

        try stdout.print("Removed {s}\n", .{opts.name});
        try self.gitCommit("Remove password for {s}", .{opts.name});
    }

    /// Find passwords by name
    pub fn find(self: *Self, writer: anytype, terms: []const []const u8) !void {
        try writer.print("Search Terms: ", .{});
        for (terms) |term| {
            try writer.print("{s} ", .{term});
        }
        try writer.print("\n", .{});

        try self.findRecursive(writer, self.store_dir, "", terms);
    }

    fn findRecursive(self: *Self, writer: anytype, base_path: []const u8, prefix: []const u8, terms: []const []const u8) !void {
        var dir = fs.openDirAbsolute(base_path, .{ .iterate = true }) catch return;
        defer dir.close();

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.name[0] == '.') continue;

            const full_name = if (prefix.len > 0)
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ prefix, entry.name })
            else
                try self.allocator.dupe(u8, entry.name);
            defer self.allocator.free(full_name);

            if (entry.kind == .directory) {
                const subpath = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ base_path, entry.name });
                defer self.allocator.free(subpath);
                try self.findRecursive(writer, subpath, full_name, terms);
            } else if (mem.endsWith(u8, entry.name, ".age")) {
                const name = full_name[0 .. full_name.len - 4]; // Strip .age

                // Check if any term matches
                var matches = false;
                for (terms) |term| {
                    if (std.ascii.indexOfIgnoreCase(name, term) != null) {
                        matches = true;
                        break;
                    }
                }

                if (matches) {
                    try writer.print("\u{2514}\u{2500}\u{2500} {s}\n", .{name});
                }
            }
        }
    }

    /// Search password contents with grep
    pub fn grep(self: *Self, writer: anytype, opts: cli.Command.GrepOptions) !void {
        try self.grepRecursive(writer, self.store_dir, "", opts.pattern);
    }

    fn grepRecursive(self: *Self, writer: anytype, base_path: []const u8, prefix: []const u8, pattern: []const u8) !void {
        var dir = fs.openDirAbsolute(base_path, .{ .iterate = true }) catch return;
        defer dir.close();

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.name[0] == '.') continue;

            const full_name = if (prefix.len > 0)
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ prefix, entry.name })
            else
                try self.allocator.dupe(u8, entry.name);
            defer self.allocator.free(full_name);

            if (entry.kind == .directory) {
                const subpath = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ base_path, entry.name });
                defer self.allocator.free(subpath);
                try self.grepRecursive(writer, subpath, full_name, pattern);
            } else if (mem.endsWith(u8, entry.name, ".age")) {
                const file_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ base_path, entry.name });
                defer self.allocator.free(file_path);

                // Decrypt and search
                const content = age.decrypt(self.allocator, file_path, self.identities_file) catch continue;
                defer utils.secureFree(self.allocator, @constCast(content));

                const name = full_name[0 .. full_name.len - 4];

                // Simple substring search (real impl would use regex)
                var lines = mem.splitSequence(u8, content, "\n");
                var line_num: u32 = 1;
                while (lines.next()) |line| {
                    if (std.ascii.indexOfIgnoreCase(line, pattern)) |_| {
                        try writer.print("{s}:{d}:{s}\n", .{ name, line_num, line });
                    }
                    line_num += 1;
                }
            }
        }
    }

    /// Copy a password (re-encrypts for destination recipients)
    pub fn copy(self: *Self, opts: cli.Command.CopyMoveOptions) !void {
        try utils.checkSneakyPaths(opts.source);
        try utils.checkSneakyPaths(opts.dest);

        const content = try self.show(self.allocator, opts.source);
        defer utils.secureFree(self.allocator, @constCast(content));

        const dest_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}.age", .{ self.store_dir, opts.dest });
        defer self.allocator.free(dest_path);

        if (!opts.force) {
            fs.accessAbsolute(dest_path, .{}) catch |err| {
                if (err != error.FileNotFound) return err;
            };
        }

        // Create parent directories
        if (std.fs.path.dirname(dest_path)) |parent| {
            fs.makeDirAbsolute(parent) catch |err| {
                if (err != error.PathAlreadyExists) return err;
            };
        }

        const recipients = try self.getRecipients(opts.dest);
        defer self.allocator.free(recipients);
        try age.encrypt(self.allocator, content, dest_path, recipients);

        try self.gitCommit("Copy {s} to {s}", .{ opts.source, opts.dest });
    }

    /// Move/rename a password
    pub fn move(self: *Self, opts: cli.Command.CopyMoveOptions) !void {
        try utils.checkSneakyPaths(opts.source);
        try utils.checkSneakyPaths(opts.dest);

        try self.copy(.{ .source = opts.source, .dest = opts.dest, .force = opts.force });

        const src_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}.age", .{ self.store_dir, opts.source });
        defer self.allocator.free(src_path);

        try fs.deleteFileAbsolute(src_path);

        try self.gitCommit("Rename {s} to {s}", .{ opts.source, opts.dest });
    }

    /// Run git commands in the store
    pub fn git(self: *Self, args: []const []const u8) !void {
        // Build argv for git command
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.allocator);

        try argv.append(self.allocator, "git");
        try argv.append(self.allocator, "-C");
        try argv.append(self.allocator, self.store_dir);
        for (args) |arg| {
            try argv.append(self.allocator, arg);
        }

        // Execute git
        var child = std.process.Child.init(argv.items, self.allocator);
        child.cwd = self.store_dir;
        _ = try child.spawnAndWait();
    }

    /// Initialize the store
    pub fn init(self: *Self) !void {
        var stdout_buf: [1024]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
        const stdout = &stdout_writer.interface;

        // Create store directory
        fs.makeDirAbsolute(self.store_dir) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };

        // Initialize git repo
        var child = std.process.Child.init(&.{ "git", "init", self.store_dir }, self.allocator);
        _ = try child.spawnAndWait();

        // Create .gitattributes for age diff
        const gitattributes_path = try std.fmt.allocPrint(self.allocator, "{s}/.gitattributes", .{self.store_dir});
        defer self.allocator.free(gitattributes_path);

        const gitattributes_file = try fs.createFileAbsolute(gitattributes_path, .{});
        defer gitattributes_file.close();
        try gitattributes_file.writeAll("*.age diff=age\n");

        // Configure git for age diff
        const age_bin = std.posix.getenv("PASSAGE_AGE") orelse "age";
        const textconv_cmd = try std.fmt.allocPrint(self.allocator, "{s} -d -i {s}", .{ age_bin, self.identities_file });
        defer self.allocator.free(textconv_cmd);

        // git config --local diff.age.binary true
        var config1 = std.process.Child.init(&.{ "git", "-C", self.store_dir, "config", "--local", "diff.age.binary", "true" }, self.allocator);
        _ = try config1.spawnAndWait();

        // git config --local diff.age.textconv "age -d -i IDENTITIES_FILE"
        var config2 = std.process.Child.init(&.{ "git", "-C", self.store_dir, "config", "--local", "diff.age.textconv", textconv_cmd }, self.allocator);
        _ = try config2.spawnAndWait();

        // Add and commit
        try self.gitCommit("Initialize password store", .{});

        try stdout.print("Password store initialized at {s}\n", .{self.store_dir});
        try stdout.flush();
    }

    /// Re-encrypt all passwords
    pub fn reencrypt(self: *Self, path: ?[]const u8) !void {
        const base = if (path) |p|
            try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.store_dir, p })
        else
            self.store_dir;
        defer if (path != null) self.allocator.free(base);

        try self.reencryptRecursive(base);
        try self.gitCommit("Reencrypt passwords in {s}", .{path orelse "store"});
    }

    fn reencryptRecursive(self: *Self, base_path: []const u8) !void {
        var dir = fs.openDirAbsolute(base_path, .{ .iterate = true }) catch return;
        defer dir.close();

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.name[0] == '.') continue;

            const full_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ base_path, entry.name });
            defer self.allocator.free(full_path);

            if (entry.kind == .directory) {
                try self.reencryptRecursive(full_path);
            } else if (mem.endsWith(u8, entry.name, ".age")) {
                // Decrypt
                const content = age.decrypt(self.allocator, full_path, self.identities_file) catch continue;
                defer utils.secureFree(self.allocator, @constCast(content));

                // Get recipients for this path
                const name = entry.name[0 .. entry.name.len - 4];
                const recipients = try self.getRecipients(name);
                defer self.allocator.free(recipients);

                // Re-encrypt
                try age.encrypt(self.allocator, content, full_path, recipients);
            }
        }
    }

    /// Get recipients for a password path. Caller must free the returned string.
    /// Implements hierarchical lookup: walks up from the password's directory looking for .age-recipients
    fn getRecipients(self: *Self, path: []const u8) ![]const u8 {
        // Check PASSAGE_RECIPIENTS_FILE env var first
        if (std.posix.getenv("PASSAGE_RECIPIENTS_FILE")) |r| {
            return try self.allocator.dupe(u8, std.mem.sliceTo(r, 0));
        }

        // Check PASSAGE_RECIPIENTS env var (space-separated recipient strings)
        if (std.posix.getenv("PASSAGE_RECIPIENTS")) |r| {
            return try self.allocator.dupe(u8, std.mem.sliceTo(r, 0));
        }

        // Walk up the directory tree looking for .age-recipients
        // Start from PREFIX/path and walk up to PREFIX
        var current_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.store_dir, path });
        defer self.allocator.free(current_path);

        while (true) {
            // Get parent directory
            const parent = std.fs.path.dirname(current_path) orelse break;

            // Don't go above store_dir
            if (!mem.startsWith(u8, parent, self.store_dir)) break;
            if (parent.len < self.store_dir.len) break;

            // Check for .age-recipients in this directory
            const recipients_file = try std.fmt.allocPrint(self.allocator, "{s}/.age-recipients", .{parent});

            if (fs.accessAbsolute(recipients_file, .{})) |_| {
                return recipients_file;
            } else |_| {
                self.allocator.free(recipients_file);
            }

            // Move up to parent
            if (mem.eql(u8, parent, self.store_dir)) break;

            const new_path = try self.allocator.dupe(u8, parent);
            self.allocator.free(current_path);
            current_path = new_path;
        }

        // Check store root for .age-recipients
        const root_recipients = try std.fmt.allocPrint(self.allocator, "{s}/.age-recipients", .{self.store_dir});
        if (fs.accessAbsolute(root_recipients, .{})) |_| {
            return root_recipients;
        } else |_| {
            self.allocator.free(root_recipients);
        }

        // Fall back to using identity file for self-encryption
        return try self.allocator.dupe(u8, self.identities_file);
    }

    /// Commit changes to git (if store is a git repo)
    fn gitCommit(self: *Self, comptime fmt: []const u8, args: anytype) !void {
        // Check if git repo
        const git_dir = try std.fmt.allocPrint(self.allocator, "{s}/.git", .{self.store_dir});
        defer self.allocator.free(git_dir);

        fs.accessAbsolute(git_dir, .{}) catch return; // Not a git repo

        const message = try std.fmt.allocPrint(self.allocator, fmt, args);
        defer self.allocator.free(message);

        // git add -A
        var add_child = std.process.Child.init(&.{ "git", "-C", self.store_dir, "add", "-A" }, self.allocator);
        _ = try add_child.spawnAndWait();

        // git commit
        var commit_child = std.process.Child.init(&.{ "git", "-C", self.store_dir, "commit", "-m", message }, self.allocator);
        _ = commit_child.spawnAndWait() catch {}; // Ignore if nothing to commit
    }
};

// =============================================================================
// TESTS
// =============================================================================

// Integration tests require age to be installed and can be run separately
test "store open and deinit" {
    // Skip in CI if HOME is not set properly
    const home = std.posix.getenv("HOME") orelse return;
    _ = home;

    const allocator = std.testing.allocator;

    // Test with custom env vars
    const old_dir = std.posix.getenv("PASSAGE_DIR");
    const old_id = std.posix.getenv("PASSAGE_IDENTITIES_FILE");
    defer {
        // Note: can't actually restore env vars in Zig, so tests should be run in isolation
        _ = old_dir;
        _ = old_id;
    }

    var store = try Store.open(allocator);
    defer store.deinit();

    // Should have allocated paths
    try std.testing.expect(store.store_dir.len > 0);
    try std.testing.expect(store.identities_file.len > 0);
}
