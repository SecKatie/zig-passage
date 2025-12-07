const std = @import("std");
const clap = @import("clap");
const Store = @import("store.zig").Store;
const utils = @import("utils.zig");

// =============================================================================
// COMMAND LINE INTERFACE - Using zig-clap
// =============================================================================
//
// This module uses zig-clap's subcommand pattern for clean CLI parsing.
// Each subcommand (show, insert, generate, etc.) has its own parser.
// =============================================================================

pub const Command = union(enum) {
    help: void,
    version: void,
    list: ?[]const u8,
    show: ShowOptions,
    insert: InsertOptions,
    generate: GenerateOptions,
    edit: []const u8,
    delete: DeleteOptions,
    find: []const []const u8,
    grep: GrepOptions,
    copy: CopyMoveOptions,
    move: CopyMoveOptions,
    git: []const []const u8,
    init: void,
    reencrypt: ?[]const u8,

    pub const ShowOptions = struct {
        name: []const u8,
        clip: bool = false,
        line: ?u32 = null,
        qrcode: bool = false,
    };

    pub const InsertOptions = struct {
        name: []const u8,
        echo: bool = false,
        multiline: bool = false,
        force: bool = false,
    };

    pub const GenerateOptions = struct {
        name: []const u8,
        length: u32 = 25,
        no_symbols: bool = false,
        clip: bool = false,
        in_place: bool = false,
        force: bool = false,
    };

    pub const DeleteOptions = struct {
        name: []const u8,
        recursive: bool = false,
        force: bool = false,
    };

    pub const GrepOptions = struct {
        pattern: []const u8,
        extra_args: []const []const u8,
    };

    pub const CopyMoveOptions = struct {
        source: []const u8,
        dest: []const u8,
        force: bool = false,
    };
};

// Subcommands enum for zig-clap
const SubCommand = enum {
    version,
    list,
    ls,
    show,
    insert,
    add,
    generate,
    edit,
    delete,
    rm,
    remove,
    find,
    search,
    grep,
    copy,
    cp,
    move,
    mv,
    rename,
    git,
    init,
    reencrypt,
};

const main_parsers = .{
    .command = clap.parsers.enumeration(SubCommand),
};

const main_params = clap.parseParamsComptime(
    \\-h, --help     Display this help and exit.
    \\-v, --version  Show version information.
    \\<command>...
    \\
);

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout_file = std.fs.File.stdout();
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = stdout_file.writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    // If no args, show list
    if (args.len <= 1) {
        var store = try Store.open(allocator);
        defer store.deinit();
        try store.list(stdout_file, null);
        try stdout.flush();
        return;
    }

    // Parse command using process args
    var iter = try std.process.ArgIterator.initWithAllocator(allocator);
    defer iter.deinit();

    // Skip program name
    _ = iter.next();

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &main_params, main_parsers, &iter, .{
        .diagnostic = &diag,
        .allocator = allocator,
        .terminating_positional = 0, // Stop after parsing the subcommand
    }) catch |err| {
        diag.reportToFile(.stderr(), err) catch {};
        return err;
    };
    defer res.deinit();

    // Handle global flags
    if (res.args.help != 0) {
        try printHelp(stdout);
        try stdout.flush();
        return;
    }
    if (res.args.version != 0) {
        try stdout.writeAll("passage v1.7.4-zig\n");
        try stdout.flush();
        return;
    }

    // Get the subcommand
    if (res.positionals[0].len == 0) {
        // No command, show list
        var store = try Store.open(allocator);
        defer store.deinit();
        try store.list(stdout_file, null);
        try stdout.flush();
        return;
    }
    const subcmd = res.positionals[0][0];

    // Dispatch to subcommand handlers (each opens store as needed)
    switch (subcmd) {
        .version => try stdout.writeAll("passage v1.7.4-zig\n"),
        .list, .ls => try handleList(allocator, &iter, stdout_file),
        .show => try handleShow(allocator, &iter),
        .insert, .add => try handleInsert(allocator, &iter),
        .generate => try handleGenerate(allocator, &iter),
        .edit => try handleEdit(allocator, &iter),
        .delete, .rm, .remove => try handleDelete(allocator, &iter),
        .find, .search => try handleFind(allocator, &iter, stdout),
        .grep => try handleGrep(allocator, &iter, stdout),
        .copy, .cp => try handleCopyMove(allocator, &iter, true),
        .move, .mv, .rename => try handleCopyMove(allocator, &iter, false),
        .git => try handleGit(allocator, &iter),
        .init => try handleInit(allocator),
        .reencrypt => try handleReencrypt(allocator, &iter),
    }
    try stdout.flush();
}

fn handleList(allocator: std.mem.Allocator, iter: *std.process.ArgIterator, stdout_file: std.fs.File) !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help  Display this help and exit.
        \\<str>
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, clap.parsers.default, iter, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        diag.reportToFile(.stderr(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        var stdout_buf: [4096]u8 = undefined;
        var stdout_writer = stdout_file.writer(&stdout_buf);
        const stdout = &stdout_writer.interface;
        try stdout.writeAll(
            \\passage ls - list passwords
            \\
            \\Usage:
            \\  passage ls [subfolder]
            \\
            \\Options:
            \\  -h, --help  Display this help and exit.
            \\
        );
        try stdout.flush();
        return;
    }

    var store = try Store.open(allocator);
    defer store.deinit();

    const subfolder = res.positionals[0];
    try store.list(stdout_file, subfolder);
}

fn handleShow(allocator: std.mem.Allocator, iter: *std.process.ArgIterator) !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help         Display this help and exit.
        \\-c, --clip         Copy to clipboard instead of printing.
        \\-q, --qrcode       Display password as QR code.
        \\-l, --line <usize> Show only the specified line number.
        \\<str>
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, clap.parsers.default, iter, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        diag.reportToFile(.stderr(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        const stdout_file = std.fs.File.stdout();
        var stdout_buf: [4096]u8 = undefined;
        var stdout_writer = stdout_file.writer(&stdout_buf);
        const stdout = &stdout_writer.interface;
        try stdout.writeAll(
            \\passage show - show password
            \\
            \\Usage:
            \\  passage show [options] name
            \\
            \\Options:
            \\  -h, --help         Display this help and exit.
            \\  -c, --clip         Copy to clipboard instead of printing.
            \\  -q, --qrcode       Display password as QR code.
            \\  -l, --line <num>   Show only the specified line number.
            \\
        );
        try stdout.flush();
        return;
    }

    const name = res.positionals[0] orelse return error.MissingArgument;
    const opts = Command.ShowOptions{
        .name = name,
        .clip = res.args.clip != 0,
        .qrcode = res.args.qrcode != 0,
        .line = if (res.args.line) |l| @intCast(l) else null,
    };

    var store = try Store.open(allocator);
    defer store.deinit();

    if (opts.qrcode) {
        try store.showQrCode(allocator, opts.name, opts.line);
        return;
    }

    if (opts.clip) {
        try store.copyToClipboard(allocator, opts.name, opts.line);
        return;
    }

    const password = try store.show(allocator, opts.name);
    defer utils.secureFree(allocator, @constCast(password));

    const stdout_file = std.fs.File.stdout();
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = stdout_file.writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    if (opts.line) |line_num| {
        var lines = std.mem.splitSequence(u8, password, "\n");
        var current: u32 = 1;
        while (lines.next()) |line| {
            if (current == line_num) {
                try stdout.writeAll(line);
                try stdout.writeAll("\n");
                break;
            }
            current += 1;
        }
    } else {
        try stdout.writeAll(password);
        if (!std.mem.endsWith(u8, password, "\n")) {
            try stdout.writeAll("\n");
        }
    }
    try stdout.flush();
}

fn handleInsert(allocator: std.mem.Allocator, iter: *std.process.ArgIterator) !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help      Display this help and exit.
        \\-e, --echo      Echo password input (visible typing).
        \\-m, --multiline Enable multiline password entry.
        \\-f, --force     Overwrite existing password without confirmation.
        \\<str>
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, clap.parsers.default, iter, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        diag.reportToFile(.stderr(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        const stdout_file = std.fs.File.stdout();
        var stdout_buf: [4096]u8 = undefined;
        var stdout_writer = stdout_file.writer(&stdout_buf);
        const stdout = &stdout_writer.interface;
        try stdout.writeAll(
            \\passage insert - insert new password
            \\
            \\Usage:
            \\  passage insert [options] name
            \\
            \\Options:
            \\  -h, --help      Display this help and exit.
            \\  -e, --echo      Echo password input (visible typing).
            \\  -m, --multiline Enable multiline password entry.
            \\  -f, --force     Overwrite existing password without confirmation.
            \\
        );
        try stdout.flush();
        return;
    }

    const name = res.positionals[0] orelse return error.MissingArgument;
    const opts = Command.InsertOptions{
        .name = name,
        .echo = res.args.echo != 0,
        .multiline = res.args.multiline != 0,
        .force = res.args.force != 0,
    };

    var store = try Store.open(allocator);
    defer store.deinit();

    try store.insert(opts);
}

fn handleGenerate(allocator: std.mem.Allocator, iter: *std.process.ArgIterator) !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help       Display this help and exit.
        \\-n, --no-symbols Do not use special symbols in password.
        \\-c, --clip       Copy to clipboard instead of printing.
        \\-i, --in-place   Replace only the first line of existing password.
        \\-f, --force      Overwrite existing password without confirmation.
        \\<str>...
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, clap.parsers.default, iter, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        diag.reportToFile(.stderr(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        const stdout_file = std.fs.File.stdout();
        var stdout_buf: [4096]u8 = undefined;
        var stdout_writer = stdout_file.writer(&stdout_buf);
        const stdout = &stdout_writer.interface;
        try stdout.writeAll(
            \\passage generate - generate new password
            \\
            \\Usage:
            \\  passage generate [options] name [length]
            \\
            \\Options:
            \\  -h, --help       Display this help and exit.
            \\  -n, --no-symbols Do not use special symbols in password.
            \\  -c, --clip       Copy to clipboard instead of printing.
            \\  -i, --in-place   Replace only the first line of existing password.
            \\  -f, --force      Overwrite existing password without confirmation.
            \\
        );
        try stdout.flush();
        return;
    }

    // Parse positionals: can be [name] or [length, name]
    var name: ?[]const u8 = null;
    var length: u32 = 25;

    if (res.positionals[0].len == 0) return error.MissingArgument;

    if (res.positionals[0].len == 1) {
        const arg = res.positionals[0][0];
        // Try to parse as length, otherwise it's the name
        if (std.fmt.parseInt(u32, arg, 10)) |len| {
            length = len;
            // Length only, need name from next arg - but we don't have it
            // So this must be the name
            name = arg;
        } else |_| {
            name = arg;
        }
    } else if (res.positionals[0].len >= 2) {
        // First might be length, second is name
        if (std.fmt.parseInt(u32, res.positionals[0][0], 10)) |len| {
            length = len;
            name = res.positionals[0][1];
        } else |_| {
            // Both are names? Take the first one
            name = res.positionals[0][0];
        }
    }

    if (name == null) return error.MissingArgument;

    const opts = Command.GenerateOptions{
        .name = name.?,
        .length = length,
        .no_symbols = res.args.@"no-symbols" != 0,
        .clip = res.args.clip != 0,
        .in_place = res.args.@"in-place" != 0,
        .force = res.args.force != 0,
    };

    var store = try Store.open(allocator);
    defer store.deinit();

    try store.generate(allocator, opts);
}

fn handleEdit(allocator: std.mem.Allocator, iter: *std.process.ArgIterator) !void {
    // Check for help flag
    const first_arg = iter.next();
    if (first_arg) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            const stdout_file = std.fs.File.stdout();
            var stdout_buf: [4096]u8 = undefined;
            var stdout_writer = stdout_file.writer(&stdout_buf);
            const stdout = &stdout_writer.interface;
            try stdout.writeAll(
                \\passage edit - edit password in editor
                \\
                \\Usage:
                \\  passage edit name
                \\
                \\Options:
                \\  -h, --help  Display this help and exit.
                \\
            );
            try stdout.flush();
            return;
        }

        var store = try Store.open(allocator);
        defer store.deinit();
        try store.edit(allocator, arg);
    } else {
        return error.MissingArgument;
    }
}

fn handleDelete(allocator: std.mem.Allocator, iter: *std.process.ArgIterator) !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help      Display this help and exit.
        \\-r, --recursive Delete directories recursively.
        \\-f, --force     Force deletion without confirmation.
        \\<str>
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, clap.parsers.default, iter, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        diag.reportToFile(.stderr(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        const stdout_file = std.fs.File.stdout();
        var stdout_buf: [4096]u8 = undefined;
        var stdout_writer = stdout_file.writer(&stdout_buf);
        const stdout = &stdout_writer.interface;
        try stdout.writeAll(
            \\passage delete - delete password
            \\
            \\Usage:
            \\  passage delete [options] name
            \\
            \\Options:
            \\  -h, --help      Display this help and exit.
            \\  -r, --recursive Delete directories recursively.
            \\  -f, --force     Force deletion without confirmation.
            \\
        );
        try stdout.flush();
        return;
    }

    const name = res.positionals[0] orelse return error.MissingArgument;
    const opts = Command.DeleteOptions{
        .name = name,
        .recursive = res.args.recursive != 0,
        .force = res.args.force != 0,
    };

    var store = try Store.open(allocator);
    defer store.deinit();

    try store.delete(opts);
}

fn handleFind(allocator: std.mem.Allocator, iter: *std.process.ArgIterator, stdout: *std.Io.Writer) !void {
    // Collect remaining args as search terms
    var terms = std.ArrayList([]const u8){};
    defer terms.deinit(allocator);

    while (iter.next()) |term| {
        // Check for help flag
        if (std.mem.eql(u8, term, "-h") or std.mem.eql(u8, term, "--help")) {
            try stdout.writeAll(
                \\passage find - search password names
                \\
                \\Usage:
                \\  passage find terms...
                \\
                \\Options:
                \\  -h, --help  Display this help and exit.
                \\
            );
            try stdout.flush();
            return;
        }
        try terms.append(allocator, term);
    }

    if (terms.items.len == 0) return error.MissingArgument;

    var store = try Store.open(allocator);
    defer store.deinit();

    try store.find(stdout, terms.items);
}

fn handleGrep(allocator: std.mem.Allocator, iter: *std.process.ArgIterator, stdout: *std.Io.Writer) !void {
    const first_arg = iter.next() orelse return error.MissingArgument;

    // Check for help flag
    if (std.mem.eql(u8, first_arg, "-h") or std.mem.eql(u8, first_arg, "--help")) {
        try stdout.writeAll(
            \\passage grep - search password contents
            \\
            \\Usage:
            \\  passage grep pattern
            \\
            \\Options:
            \\  -h, --help  Display this help and exit.
            \\
        );
        try stdout.flush();
        return;
    }

    const pattern = first_arg;

    // Collect remaining args
    var extra_args = std.ArrayList([]const u8){};
    defer extra_args.deinit(allocator);

    while (iter.next()) |arg| {
        try extra_args.append(allocator, arg);
    }

    const opts = Command.GrepOptions{
        .pattern = pattern,
        .extra_args = extra_args.items,
    };

    var store = try Store.open(allocator);
    defer store.deinit();

    try store.grep(stdout, opts);
}

fn handleCopyMove(allocator: std.mem.Allocator, iter: *std.process.ArgIterator, is_copy: bool) !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help  Display this help and exit.
        \\-f, --force Force overwrite without confirmation.
        \\<str>
        \\<str>
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, clap.parsers.default, iter, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        diag.reportToFile(.stderr(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        const stdout_file = std.fs.File.stdout();
        var stdout_buf: [4096]u8 = undefined;
        var stdout_writer = stdout_file.writer(&stdout_buf);
        const stdout = &stdout_writer.interface;
        if (is_copy) {
            try stdout.writeAll(
                \\passage copy - copy password
                \\
                \\Usage:
                \\  passage copy [options] source dest
                \\
                \\Options:
                \\  -h, --help  Display this help and exit.
                \\  -f, --force Force overwrite without confirmation.
                \\
            );
        } else {
            try stdout.writeAll(
                \\passage move - move/rename password
                \\
                \\Usage:
                \\  passage move [options] source dest
                \\
                \\Options:
                \\  -h, --help  Display this help and exit.
                \\  -f, --force Force overwrite without confirmation.
                \\
            );
        }
        try stdout.flush();
        return;
    }

    const source = res.positionals[0] orelse return error.MissingArgument;
    const dest = res.positionals[1] orelse return error.MissingArgument;

    const opts = Command.CopyMoveOptions{
        .source = source,
        .dest = dest,
        .force = res.args.force != 0,
    };

    var store = try Store.open(allocator);
    defer store.deinit();

    if (is_copy) {
        try store.copy(opts);
    } else {
        try store.move(opts);
    }
}

fn handleGit(allocator: std.mem.Allocator, iter: *std.process.ArgIterator) !void {
    // Collect remaining args
    var git_args = std.ArrayList([]const u8){};
    defer git_args.deinit(allocator);

    while (iter.next()) |arg| {
        // Check for help flag (before any git args)
        if (git_args.items.len == 0 and (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help"))) {
            const stdout_file = std.fs.File.stdout();
            var stdout_buf: [4096]u8 = undefined;
            var stdout_writer = stdout_file.writer(&stdout_buf);
            const stdout = &stdout_writer.interface;
            try stdout.writeAll(
                \\passage git - run git command on store
                \\
                \\Usage:
                \\  passage git [args...]
                \\
                \\Options:
                \\  -h, --help  Display this help and exit.
                \\
            );
            try stdout.flush();
            return;
        }
        try git_args.append(allocator, arg);
    }

    var store = try Store.open(allocator);
    defer store.deinit();

    try store.git(git_args.items);
}

fn handleInit(allocator: std.mem.Allocator) !void {
    var store = try Store.open(allocator);
    defer store.deinit();
    try store.init();
}

fn handleReencrypt(allocator: std.mem.Allocator, iter: *std.process.ArgIterator) !void {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help    Display this help and exit.
        \\    --path <str> Path to re-encrypt.
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, clap.parsers.default, iter, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        diag.reportToFile(.stderr(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        const stdout_file = std.fs.File.stdout();
        var stdout_buf: [4096]u8 = undefined;
        var stdout_writer = stdout_file.writer(&stdout_buf);
        const stdout = &stdout_writer.interface;
        try stdout.writeAll(
            \\passage reencrypt - re-encrypt passwords
            \\
            \\Usage:
            \\  passage reencrypt [options]
            \\
            \\Options:
            \\  -h, --help       Display this help and exit.
            \\      --path <dir> Path to re-encrypt.
            \\
        );
        try stdout.flush();
        return;
    }

    var store = try Store.open(allocator);
    defer store.deinit();

    try store.reencrypt(res.args.path);
}

fn printHelp(stdout: *std.Io.Writer) !void {
    try stdout.writeAll(
        \\passage - password manager using age encryption
        \\
        \\Usage:
        \\  passage [command] [options] [args]
        \\
        \\Commands:
        \\  init                     Initialize a new password store
        \\  ls, list [subfolder]     List passwords
        \\  show [-c] [-q] name      Show password (optionally copy to clipboard)
        \\  insert [-e] [-m] name    Insert new password
        \\  generate [opts] name [len]  Generate new password
        \\  edit name                Edit password in editor
        \\  rm, delete [-r] [-f] name   Delete password
        \\  find terms...            Search password names
        \\  grep pattern             Search password contents
        \\  cp, copy src dest        Copy password (re-encrypts)
        \\  mv, move src dest        Move/rename password (re-encrypts)
        \\  git [args...]            Run git command on store
        \\  reencrypt [--path=dir]   Re-encrypt passwords
        \\  version                  Show version
        \\
        \\Options:
        \\  -c, --clip      Copy to clipboard
        \\  -q, --qrcode    Display as QR code
        \\  -e, --echo      Echo password when typing
        \\  -m, --multiline Multi-line password
        \\  -n, --no-symbols  No special characters
        \\  -f, --force     Overwrite existing
        \\  -r, --recursive Delete recursively
        \\
    );
}

// =============================================================================
// TESTS
// =============================================================================

test "help command" {
    const allocator = std.testing.allocator;

    // Create a mock arg iterator
    const args = [_][]const u8{ "passage", "help" };
    _ = args;
    _ = allocator;

    // Note: Full integration tests would require mocking Store
    // For now, we're just ensuring the code compiles
}

test "version command" {
    const allocator = std.testing.allocator;
    _ = allocator;

    // Basic compilation test
}
