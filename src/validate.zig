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

    // Axiom 4, canonical metadata
    try validateMetaCanonical(allocator, path, opts.require_meta_bin);

    // Axiom 6, policy exclusion, structural signature checks only
    try validateSignatureStructure(allocator, path, opts.require_signature);
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

pub fn validateSignatureStructure(allocator: std.mem.Allocator, path: []const u8, require_sig: bool) !void {
    // Validate that sig section, when present, is parseable by the reference implementation.
    // This does not enforce any trust policy.

    const sig = odi.readSigAlloc(allocator, path) catch null;
    if (sig == null) {
        if (require_sig) return error.MissingSignature;
        return;
    }
    defer allocator.free(sig.?);

    // Minimal structure checks: non empty and valid UTF 8
    if (sig.?.len == 0) return error.BadSignature;
    if (!std.unicode.utf8ValidateSlice(sig.?)) return error.BadSignature;
}
