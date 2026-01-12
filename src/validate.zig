const std = @import("std");
const odi = @import("odi.zig");
const odm = @import("odm.zig");

pub const Axiom = enum {
    determinism,
    section_authority,
    independent_verification,
    canonical_metadata,
    explicit_immutability,
    policy_exclusion,
    artifact_identity,
};

pub const Violation = struct {
    axiom: Axiom,
    code: []const u8,
    detail: []const u8,
};

pub const ValidateOptions = struct {
    require_signature: bool = false,
    require_meta_bin: bool = false,
};

pub fn validateAll(allocator: std.mem.Allocator, path: []const u8, opts: ValidateOptions) !void {
    // Axiom 2, section authority, structural validity
    try validateContainer(path);

    // Axiom 3, independent verification
    try validateSectionHashes(allocator, path);

    // Manifest schema (supports check-tree correctness)
    try validateManifestSchema(allocator, path);

    // Axiom 4, canonical metadata
    try validateMetaCanonical(allocator, path, opts.require_meta_bin);

    // Axiom 6, policy exclusion, structural signature checks only
    try validateSignatureStructure(allocator, path, opts.require_signature);
}


pub fn validateManifestSchema(allocator: std.mem.Allocator, path: []const u8) !void {
    // If manifest section is missing, treat as violation only when require_manifest is used by verify.
    // Here we validate schema only if present.
    const bytes = odi.readManifestAlloc(allocator, path) catch return;
    defer allocator.free(bytes);

    // validateManifestAlloc will parse strictly and fail if bad
    try odi.validateManifestAlloc(allocator, path);
}

pub fn validateContainer(path: []const u8) !void {
    var f = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
    defer f.close();

    const st = try f.stat();
    const file_len: u64 = @intCast(st.size);

    var of = try odi.OdiFile.readFromFile(std.heap.page_allocator, f);
    defer of.deinit(std.heap.page_allocator);

    // Header checks and table sanity are inside validateStructure
    try of.validateStructure(file_len);
}

pub fn validateSectionHashes(allocator: std.mem.Allocator, path: []const u8) !void {
    _ = allocator;
    // Delegate to existing verify implementation
    // Axiom 3 requires section local hashing
    try odi.verifyFile(path, .{});
}

pub fn validateMetaCanonical(allocator: std.mem.Allocator, path: []const u8, require_meta_bin: bool) !void {
    // Prefer ODM meta_bin when present.
    const meta_bin = odi.readMetaBinAlloc(allocator, path) catch null;
    if (meta_bin == null and require_meta_bin) return error.MissingMetaBin;
    if (meta_bin != null) {
        defer allocator.free(meta_bin.?);
        try odm.validateCanonical(meta_bin.?);
        return;
    }

    // Fall back to canonical JSON META.
    const meta_bytes = try odi.readMetaAlloc(allocator, path);
    defer allocator.free(meta_bytes);

    const canon = try odi.canonicalizeMetaAlloc(allocator, meta_bytes);
    defer allocator.free(canon);

    if (!std.mem.eql(u8, meta_bytes, canon)) {
        return error.MetaNotCanonical;
    }
}

pub fn validateSignatureStructure(allocator: std.mem.Allocator, path: []const u8) !void {
    const sig = odi.readSigAlloc(allocator, path) catch null;
    if (sig == null) return;
    defer allocator.free(sig.?);

    // Must be UTF-8
    if (!std.unicode.utf8ValidateSlice(sig.?)) return error.InvalidSignatureUtf8;

    // Expect OpenSSH sshsig ASCII armor.
    // Minimal strict grammar:
    //   -----BEGIN SSH SIGNATURE-----
    //   <base64 lines>
    //   -----END SSH SIGNATURE-----
    //
    const begin = "-----BEGIN SSH SIGNATURE-----";
    const end = "-----END SSH SIGNATURE-----";

    var it = std.mem.splitScalar(u8, sig.?, '\n');

    const first = it.next() orelse return error.InvalidSignatureArmor;
    if (!std.mem.eql(u8, std.mem.trimRight(u8, first, "\r"), begin)) return error.InvalidSignatureArmor;

    var saw_end = false;
    var saw_b64 = false;

    while (it.next()) |line_raw| {
        const line = std.mem.trimRight(u8, line_raw, "\r");
        if (line.len == 0) continue;

        if (std.mem.eql(u8, line, end)) {
            saw_end = true;
            break;
        }

        // base64 line: characters A-Z a-z 0-9 + / =
        for (line) |c| {
            const ok = (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '+' or c == '/' or c == '=';
            if (!ok) return error.InvalidSignatureArmor;
        }
        saw_b64 = true;
    }

    if (!saw_end or !saw_b64) return error.InvalidSignatureArmor;

    // No non-empty trailing lines after END marker.
    while (it.next()) |tail_raw| {
        const tail = std.mem.trim(u8, tail_raw, " \t\r\n");
        if (tail.len != 0) return error.InvalidSignatureArmor;
    }
}
