const std = @import("std");
const odi = @import("odi");
const validate = @import("validate");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args_it = try std.process.argsWithAllocator(allocator);
    defer args_it.deinit();

    var args: std.ArrayListUnmanaged([]const u8) = .{};
    defer args.deinit(allocator);

    while (args_it.next()) |a| try args.append(allocator, a);

    const stdout: std.fs.File = .{ .handle = std.posix.STDOUT_FILENO };

    if (args.items.len < 2) {
        try stdout.writeAll(usage());
        return;
    }

    const cmd = args.items[1];

    if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        try stdout.writeAll(usage());
        return;
    }

    if (std.mem.eql(u8, cmd, "dump-manifest")) {
        try cmdManifestDump(allocator, args.items[2..]);
        return;
    }
    if (std.mem.eql(u8, cmd, "diff-manifest")) {
        try cmdManifestDiff(allocator, args.items[2..]);
        return;
    }
    if (std.mem.eql(u8, cmd, "validate")) {
        try cmdValidate(allocator, args.items[2..]);
        return;
    }

    if (std.mem.eql(u8, cmd, "verify")) {
        try cmdVerify(allocator, args.items[2..]);
        return;
    }
    if (std.mem.eql(u8, cmd, "manifest")) {
        try cmdManifest(allocator, args.items[2..]);
        return;
    }
    if (std.mem.eql(u8, cmd, "sign")) {
        try cmdSign(allocator, args.items[2..]);
        return;
    }
    if (std.mem.eql(u8, cmd, "meta")) {
        try cmdMeta(allocator, args.items[2..]);
        return;
    }

    var print_buf: [256]u8 = undefined;
    const print_msg = std.fmt.bufPrint(&print_buf, "Unknown command: {s}\n\n", .{cmd}) catch "Unknown command\n\n";
    try stdout.writeAll(print_msg);
    try stdout.writeAll(usage());
}

fn usage() []const u8 {
    return
        \\ODI reference implementation (Zig 0.15.2)
        \\
        \\Usage:
        \\  odi help
        \\  odi verify [--json] [--verify-hashes] [--require-manifest] [--require-signature --allowed-signers <file> --identity <principal> [--ssh-keygen <path>]] <file.odi>
        \\
        \\Manifest commands:
        \\  odi manifest dump <file.odi> [--json]
        \\  odi manifest diff [--json] [--content-only] [--limit N] [--fail-fast]
        \\                   [--paths-from <file>] [--exclude <glob>]... [--exclude-from <file>]
        \\                   <a.odi> <b.odi>
        \\  odi manifest check-tree [--json] [--content-only] [--limit N] [--fail-fast]
        \\                          [--paths-from <file>] [--exclude <glob>]... [--exclude-from <file>]
        \\                          <root-dir> <file.odi>
        \\  odi manifest hash <file.odi> [--json]
        \\  odi manifest attest <file.odi> [--json] [--verify]
        \\  odi manifest provenance <file.odi> [--json] [--verify]
        \\
        \\Aliases:
        \\  odi dump-manifest == odi manifest dump
        \\  odi diff-manifest == odi manifest diff
        \\
        \\Meta commands (write new ODI):
        \\  odi meta get <file.odi> <json-pointer> [--json]
        \\  odi meta set <file.odi> <json-pointer> <value> --out <new.odi> [--strip-signature]
        \\  odi meta patch <file.odi> --patch <file.json> --out <new.odi> [--strip-signature]
        \\
        \\Signing:
        \\  odi sign <in.odi> --out <signed.odi> --key <private_key> --identity <principal> [--ssh-keygen <path>] [--no-verify]
        \\
    ;
}

fn cmdManifest(allocator: std.mem.Allocator, args: [][]const u8) !void {
    if (args.len == 0) return error.MissingArgument;
    const sub = args[0];

    if (std.mem.eql(u8, sub, "dump")) return cmdManifestDump(allocator, args[1..]);
    if (std.mem.eql(u8, sub, "diff")) return cmdManifestDiff(allocator, args[1..]);
    if (std.mem.eql(u8, sub, "check-tree")) return cmdManifestCheckTree(allocator, args[1..]);
    if (std.mem.eql(u8, sub, "hash")) return cmdManifestHash(allocator, args[1..]);
    if (std.mem.eql(u8, sub, "attest")) return cmdManifestAttest(allocator, args[1..]);
    if (std.mem.eql(u8, sub, "provenance")) return cmdManifestProvenance(allocator, args[1..]);

    return error.UnknownArgument;
}

fn cmdManifestDump(allocator: std.mem.Allocator, args: [][]const u8) !void {
    var json = false;
    var odi_path: ?[]const u8 = null;

    for (args) |a| {
        if (std.mem.eql(u8, a, "--json")) {
            json = true;
        } else {
            odi_path = a;
        }
    }
    if (odi_path == null) return error.MissingArgument;

    const manifest_bytes = try odi.readManifestAlloc(allocator, odi_path.?);
    defer allocator.free(manifest_bytes);

    const stdout: std.fs.File = .{ .handle = std.posix.STDOUT_FILENO };
    if (!json) {
        try stdout.writeAll(manifest_bytes);
        try stdout.writeAll("\n");
        return;
    }

    const wrapped = try odi.wrapManifestJsonAlloc(allocator, manifest_bytes);
    defer allocator.free(wrapped);
    try stdout.writeAll(wrapped);
    try stdout.writeAll("\n");
}

fn cmdManifestDiff(allocator: std.mem.Allocator, args: [][]const u8) !void {
    var json = false;
    var content_only = false;
    var limit: usize = 0;
    var fail_fast = false;

    var paths_from: ?[]const u8 = null;
    var exclude_from: ?[]const u8 = null;
    var excludes: std.ArrayListUnmanaged([]const u8) = .{};
    defer excludes.deinit(allocator);

    var a_path: ?[]const u8 = null;
    var b_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];

        if (std.mem.eql(u8, a, "--json")) { json = true; continue; }
        if (std.mem.eql(u8, a, "--content-only")) { content_only = true; continue; }
        if (std.mem.eql(u8, a, "--fail-fast")) { fail_fast = true; continue; }

        if (std.mem.eql(u8, a, "--limit")) {
            i += 1; if (i >= args.len) return error.MissingValue;
            limit = try std.fmt.parseInt(usize, args[i], 10);
            continue;
        }
        if (std.mem.eql(u8, a, "--paths-from")) {
            i += 1; if (i >= args.len) return error.MissingValue;
            paths_from = args[i];
            continue;
        }
        if (std.mem.eql(u8, a, "--exclude-from")) {
            i += 1; if (i >= args.len) return error.MissingValue;
            exclude_from = args[i];
            continue;
        }
        if (std.mem.eql(u8, a, "--exclude")) {
            i += 1; if (i >= args.len) return error.MissingValue;
            try excludes.append(allocator, args[i]);
            continue;
        }

        if (a_path == null) { a_path = a; continue; }
        if (b_path == null) { b_path = a; continue; }

        return error.UnknownArgument;
    }

    if (a_path == null or b_path == null) return error.MissingArgument;

    const a_bytes = try odi.readManifestAlloc(allocator, a_path.?);
    defer allocator.free(a_bytes);
    const b_bytes = try odi.readManifestAlloc(allocator, b_path.?);
    defer allocator.free(b_bytes);

    const mode = odi.DiffMode{ .content_only = content_only };
    const policy = odi.DiffPolicy{ .limit = limit, .fail_fast = fail_fast };
    const filter = odi.DiffFilter{
        .paths_from = paths_from,
        .exclude_from = exclude_from,
        .exclude_globs = excludes.items,
    };

    const stdout: std.fs.File = .{ .handle = std.posix.STDOUT_FILENO };
    if (json) {
        const j = try odi.diffManifestJsonAllocFull(allocator, a_bytes, b_bytes, mode, policy, filter);
        defer allocator.free(j);
        try stdout.writeAll(j);
        try stdout.writeAll("\n");
    } else {
        const t = try odi.diffManifestAllocFull(allocator, a_bytes, b_bytes, mode, policy, filter);
        defer allocator.free(t);
        try stdout.writeAll(t);
        try stdout.writeAll("\n");
    }
}

fn cmdManifestCheckTree(allocator: std.mem.Allocator, args: [][]const u8) !void {
    var json = false;
    var content_only = false;
    var limit: usize = 0;
    var fail_fast = false;

    var root_dir: ?[]const u8 = null;
    var odi_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];

        if (std.mem.eql(u8, a, "--json")) { json = true; continue; }
        if (std.mem.eql(u8, a, "--content-only")) { content_only = true; continue; }
        if (std.mem.eql(u8, a, "--fail-fast")) { fail_fast = true; continue; }
        if (std.mem.eql(u8, a, "--limit")) {
            i += 1; if (i >= args.len) return error.MissingValue;
            limit = try std.fmt.parseInt(usize, args[i], 10);
            continue;
        }

        if (root_dir == null) { root_dir = a; continue; }
        if (odi_path == null) { odi_path = a; continue; }
        return error.UnknownArgument;
    }

    if (root_dir == null or odi_path == null) return error.MissingArgument;

    const report = try odi.checkTreeAgainstManifestAlloc(.{
        .allocator = allocator,
        .root_dir = root_dir.?,
        .odi_path = odi_path.?,
        .mode = .{ .content_only = content_only },
        .policy = .{ .limit = limit, .fail_fast = fail_fast },
    });
    defer report.deinit(allocator);

    const stdout: std.fs.File = .{ .handle = std.posix.STDOUT_FILENO };
    if (json) {
        const j = try report.toJsonAlloc(allocator);
        defer allocator.free(j);
        try stdout.writeAll(j);
        try stdout.writeAll("\n");
    } else {
        const t = try report.toTextAlloc(allocator);
        defer allocator.free(t);
        try stdout.writeAll(t);
        try stdout.writeAll("\n");
    }

    if (!report.ok) return error.VerifyFailed;
}

fn cmdManifestHash(allocator: std.mem.Allocator, args: [][]const u8) !void {
    var json = false;
    var odi_path: ?[]const u8 = null;

    for (args) |a| {
        if (std.mem.eql(u8, a, "--json")) {
            json = true;
        } else {
            odi_path = a;
        }
    }
    if (odi_path == null) return error.MissingArgument;

    const info = try odi.readSectionHashInfoAlloc(allocator, odi_path.?);
    defer info.deinit(allocator);

    const stdout: std.fs.File = .{ .handle = std.posix.STDOUT_FILENO };
    if (json) {
        const j = try odi.sectionHashInfoToJsonAlloc(allocator, odi_path.?, info);
        defer allocator.free(j);
        try stdout.writeAll(j);
        try stdout.writeAll("\n");
        return;
    }

    const text = try odi.sectionHashInfoToTextAlloc(allocator, info);
    defer allocator.free(text);
    try stdout.writeAll(text);
}

fn cmdManifestAttest(allocator: std.mem.Allocator, args: [][]const u8) !void {
    var json = false;
    var verify = false;
    var odi_path: ?[]const u8 = null;

    for (args) |a| {
        if (std.mem.eql(u8, a, "--json")) json = true
        else if (std.mem.eql(u8, a, "--verify")) verify = true
        else odi_path = a;
    }
    if (odi_path == null) return error.MissingArgument;

    const att = try odi.attestFromFileAlloc(allocator, odi_path.?, verify, null);
    defer att.deinit(allocator);

    const stdout: std.fs.File = .{ .handle = std.posix.STDOUT_FILENO };
    if (json) {
        const j = try att.toJsonAlloc(allocator);
        defer allocator.free(j);
        try stdout.writeAll(j);
        try stdout.writeAll("\n");
    } else {
        const line = try att.toLineAlloc(allocator);
        defer allocator.free(line);
        try stdout.writeAll(line);
        try stdout.writeAll("\n");
    }
}

fn cmdManifestProvenance(allocator: std.mem.Allocator, args: [][]const u8) !void {
    var json = false;
    var verify = false;
    var odi_path: ?[]const u8 = null;

    for (args) |a| {
        if (std.mem.eql(u8, a, "--json")) json = true
        else if (std.mem.eql(u8, a, "--verify")) verify = true
        else odi_path = a;
    }
    if (odi_path == null) return error.MissingArgument;

    const prov = try odi.provenanceFromFileAlloc(allocator, odi_path.?, verify);
    defer prov.deinit(allocator);

    const stdout: std.fs.File = .{ .handle = std.posix.STDOUT_FILENO };
    if (json) {
        const j = try prov.toJsonAlloc(allocator);
        defer allocator.free(j);
        try stdout.writeAll(j);
        try stdout.writeAll("\n");
    } else {
        const t = try prov.toTextAlloc(allocator);
        defer allocator.free(t);
        try stdout.writeAll(t);
        try stdout.writeAll("\n");
    }
}

fn cmdValidate(allocator: std.mem.Allocator, args: [][]const u8) !void {
    if (args.len < 1) return error.MissingArgument;
    const path = args[0];

    var require_sig = false;
    var require_meta_bin = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--require-signature")) {
            require_sig = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--require-meta-bin")) {
            require_meta_bin = true;
            continue;
        }
        return error.UnknownArgument;
    }

    try validate.validateAll(allocator, path, .{
        .require_signature = require_sig,
        .require_meta_bin = require_meta_bin,
    });
}

fn cmdVerify(allocator: std.mem.Allocator, args: [][]const u8) !void {
    var json = false;
    var verify_hashes = false;
    var require_manifest = false;
    var require_meta_bin = false;

    var require_sig = false;
    var require_sig_binds_meta_bin = false;
    var allowed_signers: ?[]const u8 = null;
    var identity: ?[]const u8 = null;
    var ssh_keygen_path: []const u8 = "ssh-keygen";

    var odi_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--json")) { json = true; continue; }
        if (std.mem.eql(u8, a, "--verify-hashes")) { verify_hashes = true; continue; }
        if (std.mem.eql(u8, a, "--require-manifest")) { require_manifest = true; continue; }
        if (std.mem.eql(u8, a, "--require-meta-bin")) { require_meta_bin = true; continue; }
        if (std.mem.eql(u8, a, "--require-signature")) { require_sig = true; continue; }
        if (std.mem.eql(u8, a, "--require-sig-binds-meta-bin")) { require_sig_binds_meta_bin = true; continue; }

        if (std.mem.eql(u8, a, "--allowed-signers")) {
            i += 1; if (i >= args.len) return error.MissingValue;
            allowed_signers = args[i];
            continue;
        }
        if (std.mem.eql(u8, a, "--identity")) {
            i += 1; if (i >= args.len) return error.MissingValue;
            identity = args[i];
            continue;
        }
        if (std.mem.eql(u8, a, "--ssh-keygen")) {
            i += 1; if (i >= args.len) return error.MissingValue;
            ssh_keygen_path = args[i];
            continue;
        }

        odi_path = a;
    }

    if (odi_path == null) return error.MissingArgument;

    var report = try odi.verifyFileAlloc(.{
        .allocator = allocator,
        .odi_path = odi_path.?,
        .verify_hashes = verify_hashes,
        .require_manifest = require_manifest,
        .require_meta_bin = require_meta_bin,
        .require_signature = require_sig,
        .require_sig_binds_meta_bin = require_sig_binds_meta_bin,
        .allowed_signers = allowed_signers,
        .identity = identity,
        .ssh_keygen_path = ssh_keygen_path,
    });
    defer report.deinit(allocator);

    const stdout: std.fs.File = .{ .handle = std.posix.STDOUT_FILENO };
    if (json) {
        const j = try report.toJsonAlloc(allocator);
        defer allocator.free(j);
        try stdout.writeAll(j);
        try stdout.writeAll("\n");
    } else {
        const t = try report.toTextAlloc(allocator);
        defer allocator.free(t);
        try stdout.writeAll(t);
        try stdout.writeAll("\n");
    }

    if (!report.ok) return error.VerifyFailed;
}

fn cmdMeta(allocator: std.mem.Allocator, args: [][]const u8) !void {
    if (args.len == 0) return error.MissingArgument;
    const sub = args[0];

    if (std.mem.eql(u8, sub, "get")) {
        if (args.len < 3) return error.MissingArgument;
        const odi_path = args[1];
        const ptr = args[2];
        const _json_flag = (args.len >= 4 and std.mem.eql(u8, args[3], "--json"));
        _ = _json_flag; // currently always emits JSON-minified

        const val_json = try odi.metaPointerGetEffectiveAlloc(allocator, odi_path, ptr);
        defer allocator.free(val_json);

        const stdout: std.fs.File = .{ .handle = std.posix.STDOUT_FILENO };
        try stdout.writeAll(val_json);
        try stdout.writeAll("\n");
        return;
    }

    if (std.mem.eql(u8, sub, "set")) {
        if (args.len < 5) return error.MissingArgument;
        const odi_path = args[1];
        const ptr = args[2];
        const value = args[3];

        const has_meta_bin = (odi.readMetaBinAlloc(allocator, odi_path) catch null) != null;

        var out_path: ?[]const u8 = null;
        var strip_sig = false;

        var force_json = false;
        var force_string = false;

        var i: usize = 4;
        while (i < args.len) : (i += 1) {
            const a = args[i];
            if (std.mem.eql(u8, a, "--out")) {
                i += 1; if (i >= args.len) return error.MissingValue;
                out_path = args[i];
                continue;
            }
            if (std.mem.eql(u8, a, "--strip-signature")) {
                strip_sig = true;
                continue;
            }
            if (std.mem.eql(u8, a, "--json-value")) {
                force_json = true;
                continue;
            }
            if (std.mem.eql(u8, a, "--string")) {
                force_string = true;
                continue;
            }
            return error.UnknownArgument;
        }

        if (out_path == null) return error.MissingArgument;
        if (force_json and force_string) return error.BadArgument;

        if (has_meta_bin) {
            try odi.rewriteMetaBinSet(.{
                .allocator = allocator,
                .in_path = odi_path,
                .out_path = out_path.?,
                .json_pointer = ptr,
                .value_bytes = value,
                .value_mode = if (force_json) .json else if (force_string) .string else .auto,
                .strip_signature = strip_sig,
            });
        } else {
            try odi.rewriteMetaSet(.{
                .allocator = allocator,
                .in_path = odi_path,
                .out_path = out_path.?,
                .json_pointer = ptr,
                .value_bytes = value,
                .value_mode = if (force_json) .json else if (force_string) .string else .auto,
                .strip_signature = strip_sig,
            });
        }
        return;
    }

    if (std.mem.eql(u8, sub, "patch")) {
        if (args.len < 2) return error.MissingArgument;
        const odi_path = args[1];

        const has_meta_bin = (odi.readMetaBinAlloc(allocator, odi_path) catch null) != null;

        var patch_path: ?[]const u8 = null;
        var out_path: ?[]const u8 = null;
        var strip_sig = false;

        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            const a = args[i];
            if (std.mem.eql(u8, a, "--patch")) {
                i += 1; if (i >= args.len) return error.MissingValue;
                patch_path = args[i];
                continue;
            }
            if (std.mem.eql(u8, a, "--out")) {
                i += 1; if (i >= args.len) return error.MissingValue;
                out_path = args[i];
                continue;
            }
            if (std.mem.eql(u8, a, "--strip-signature")) {
                strip_sig = true;
                continue;
            }
            return error.UnknownArgument;
        }

        if (patch_path == null or out_path == null) return error.MissingArgument;

        if (has_meta_bin) {
            try odi.rewriteMetaBinPatch(.{
                .allocator = allocator,
                .in_path = odi_path,
                .out_path = out_path.?,
                .patch_json_path = patch_path.?,
                .strip_signature = strip_sig,
            });
        } else {
            try odi.rewriteMetaPatch(.{
                .allocator = allocator,
                .in_path = odi_path,
                .out_path = out_path.?,
                .patch_json_path = patch_path.?,
                .strip_signature = strip_sig,
            });
        }
        return;
    }

    return error.UnknownArgument;
}

fn cmdSign(allocator: std.mem.Allocator, args: [][]const u8) !void {
    var in_path: ?[]const u8 = null;
    var out_path: ?[]const u8 = null;
    var key_path: ?[]const u8 = null;
    var identity: ?[]const u8 = null;
    var ssh_keygen_path: []const u8 = "ssh-keygen";
    var do_verify = true;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];

        if (std.mem.eql(u8, a, "--out")) {
            i += 1; if (i >= args.len) return error.MissingValue;
            out_path = args[i];
            continue;
        }
        if (std.mem.eql(u8, a, "--key")) {
            i += 1; if (i >= args.len) return error.MissingValue;
            key_path = args[i];
            continue;
        }
        if (std.mem.eql(u8, a, "--identity")) {
            i += 1; if (i >= args.len) return error.MissingValue;
            identity = args[i];
            continue;
        }
        if (std.mem.eql(u8, a, "--ssh-keygen")) {
            i += 1; if (i >= args.len) return error.MissingValue;
            ssh_keygen_path = args[i];
            continue;
        }
        if (std.mem.eql(u8, a, "--no-verify")) {
            do_verify = false;
            continue;
        }

        if (in_path == null) { in_path = a; continue; }
        return error.UnknownArgument;
    }

    if (in_path == null or out_path == null or key_path == null or identity == null) {
        return error.MissingArgument;
    }

    try odi.signOdiFile(.{
        .allocator = allocator,
        .in_path = in_path.?,
        .out_path = out_path.?,
        .key_path = key_path.?,
        .identity = identity.?,
        .ssh_keygen_path = ssh_keygen_path,
        .verify_before_sign = do_verify,
        .strip_existing_sig = true,
    });
}






