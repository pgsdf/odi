const std = @import("std");

pub const SectionType = enum(u32) {
    payload = 1,
    meta = 2,
    manifest = 3,
    sig = 4,
    meta_bin = 5,
};

pub const HashAlg = enum(u8) {
    none = 0,
    sha256 = 1,
};

pub const Header = extern struct {
    magic: [4]u8,          // "ODI1"
    version: u16,          // 1
    section_count: u16,
    table_offset: u64,
    table_length: u64,
    reserved: [32]u8,

    pub fn initDefault() Header {
        var h: Header = undefined;
        h.magic = .{ 'O', 'D', 'I', '1' };
        h.version = 1;
        h.section_count = 0;
        h.table_offset = @sizeOf(Header);
        h.table_length = 0;
        @memset(&h.reserved, 0);
        return h;
    }

    pub fn validate(self: Header) !void {
        if (!std.mem.eql(u8, &self.magic, "ODI1")) return error.BadMagic;
        if (self.version != 1) return error.UnsupportedVersion;
    }
};

pub const Section = extern struct {
    stype: u32,
    reserved0: u32,
    offset: u64,
    length: u64,
    hash_alg: u8,
    hash_len: u8,
    reserved1: u16,
    hash: [64]u8,
};

pub const OdiFile = struct {
    header: Header,
    sections: []Section,

    pub fn deinit(self: *OdiFile, allocator: std.mem.Allocator) void {
        allocator.free(self.sections);
    }

    pub fn readFromFile(allocator: std.mem.Allocator, file: std.fs.File) !OdiFile {
        var h: Header = undefined;
        try file.seekTo(0);
        try file.reader().readNoEof(std.mem.asBytes(&h));
        try h.validate();

        if (h.table_length != @as(u64, h.section_count) * @sizeOf(Section)) return error.BadSectionTable;

        try file.seekTo(h.table_offset);
        const count: usize = @intCast(h.section_count);
        const secs = try allocator.alloc(Section, count);
        errdefer allocator.free(secs);

        const bytes = std.mem.sliceAsBytes(secs);
        try file.reader().readNoEof(bytes);

        return .{ .header = h, .sections = secs };
    }

    pub fn findSection(self: *const OdiFile, t: SectionType) ?Section {
        const want: u32 = @intFromEnum(t);
        for (self.sections) |s| {
            if (s.stype == want) return s;
        }
        return null;
    }

    pub fn validateStructure(self: *const OdiFile, file_len: u64) !void {
        try self.header.validate();
        for (self.sections) |s| {
            if (s.offset + s.length > file_len) return error.SectionOutOfRange;
            if (s.hash_len > s.hash.len) return error.BadHashLen;
        }
    }

    pub fn verifySectionHashes(self: *const OdiFile, file: std.fs.File) !void {
        for (self.sections) |s| {
            const alg: HashAlg = @enumFromInt(s.hash_alg);
            if (alg == .none) continue;

            if (alg != .sha256) return error.UnsupportedHashAlg;
            if (s.hash_len != 32) return error.BadHashLen;

            const got = try sha256Section(file, s.offset, s.length);
            if (!std.mem.eql(u8, got[0..], s.hash[0..32])) return error.HashMismatch;
        }
    }
};

fn sha256Section(file: std.fs.File, offset: u64, length: u64) ![32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    try file.seekTo(offset);

    var remaining: u64 = length;
    var buf: [1024 * 1024]u8 = undefined;

    while (remaining > 0) {
        const want: usize = @intCast(@min(remaining, buf.len));
        const got = try file.read(buf[0..want]);
        if (got == 0) return error.UnexpectedEof;
        hasher.update(buf[0..got]);
        remaining -= got;
    }

    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

fn sha256Bytes(bytes: []const u8) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(bytes);
    var d: [32]u8 = undefined;
    h.final(&d);
    return d;
}

fn readSectionAlloc(allocator: std.mem.Allocator, file: std.fs.File, offset: u64, length: u64, max: usize) ![]u8 {
    if (length > max) return error.SectionTooLarge;
    try file.seekTo(offset);
    const n: usize = @intCast(length);
    const buf = try allocator.alloc(u8, n);
    errdefer allocator.free(buf);
    try file.reader().readNoEof(buf);
    return buf;
}

pub fn readManifestAlloc(allocator: std.mem.Allocator, odi_path: []const u8) ![]u8 {
    var file = try std.fs.cwd().openFile(odi_path, .{ .mode = .read_only });
    defer file.close();

    const st = try file.stat();
    const file_len: u64 = @intCast(st.size);

    var of = try OdiFile.readFromFile(allocator, file);
    defer of.deinit(allocator);

    try of.validateStructure(file_len);

    const ms = of.findSection(.manifest) orelse return error.MissingManifest;
    return try readSectionAlloc(allocator, file, ms.offset, ms.length, 32 * 1024 * 1024);
}

pub fn validateManifestAlloc(allocator: std.mem.Allocator, odi_path: []const u8) !void {
    const bytes = try readManifestAlloc(allocator, odi_path);
    defer allocator.free(bytes);

    var m = try parseManifestToMap(allocator, bytes);
    defer freeManifestMap(allocator, &m);
}


pub fn wrapManifestJsonAlloc(allocator: std.mem.Allocator, manifest_bytes: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var root = std.json.ObjectMap.init(a);
    try root.put("type", .{ .string = "manifest" });

    const parsed = try std.json.parseFromSlice(std.json.Value, a, manifest_bytes, .{});
    try root.put("data", parsed.value);

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try std.json.stringify(.{ .object = root }, .{ .whitespace = .minified }, buf.writer());
    return buf.toOwnedSlice();
}

pub const DiffMode = struct { content_only: bool = false };
pub const DiffPolicy = struct { limit: usize = 0, fail_fast: bool = false };
pub const DiffFilter = struct {
    paths_from: ?[]const u8 = null,
    exclude_from: ?[]const u8 = null,
    exclude_globs: []const []const u8 = &.{},
};

pub fn diffManifestAllocFull(
    allocator: std.mem.Allocator,
    a_bytes: []const u8,
    b_bytes: []const u8,
    mode: DiffMode,
    policy: DiffPolicy,
    filter: DiffFilter,
) ![]u8 {
    const r = try diffManifestResultAlloc(allocator, a_bytes, b_bytes, mode, policy, filter);
    defer r.deinit(allocator);
    return r.toTextAlloc(allocator, mode, policy, filter);
}

pub fn diffManifestJsonAllocFull(
    allocator: std.mem.Allocator,
    a_bytes: []const u8,
    b_bytes: []const u8,
    mode: DiffMode,
    policy: DiffPolicy,
    filter: DiffFilter,
) ![]u8 {
    const r = try diffManifestResultAlloc(allocator, a_bytes, b_bytes, mode, policy, filter);
    defer r.deinit(allocator);
    return r.toJsonAlloc(allocator, mode, policy, filter);
}

// Manifest model: { "entries": [ { "path": "...", "kind":"file|dir|symlink", "mode":..., "uid":..., "gid":..., "mtime":..., "size":..., "sha256":"...", "target":"..." } ] }
// This is intentionally tolerant; unknown fields ignored.
const ManifestEntry = struct {
    kind: []u8,
    mode: ?u32 = null,
    uid: ?u32 = null,
    gid: ?u32 = null,
    mtime: ?i64 = null,
    size: ?u64 = null,
    sha256: ?[]u8 = null,
    target: ?[]u8 = null,

    fn deinit(self: *ManifestEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.kind);
        if (self.sha256) |s| allocator.free(s);
        if (self.target) |t| allocator.free(t);
    }
};

const DiffChanged = struct {
    path: []const u8,
    reason: []const u8,
    from: ?[]const u8 = null,
    to: ?[]const u8 = null,
};

pub const ManifestDiffResult = struct {
    added: [][]const u8,
    removed: [][]const u8,
    changed: []DiffChanged,

    pub fn deinit(self: *const ManifestDiffResult, allocator: std.mem.Allocator) void {
        for (self.added) |p| allocator.free(p);
        allocator.free(self.added);

        for (self.removed) |p| allocator.free(p);
        allocator.free(self.removed);

        for (self.changed) |c| {
            allocator.free(c.path);
            allocator.free(c.reason);
            if (c.from) |f| allocator.free(f);
            if (c.to) |t| allocator.free(t);
        }
        allocator.free(self.changed);
    }

    pub fn counts(self: *const ManifestDiffResult) struct { added: usize, removed: usize, changed: usize } {
        return .{ .added = self.added.len, .removed = self.removed.len, .changed = self.changed.len };
    }

    pub fn ok(self: *const ManifestDiffResult) bool {
        return self.added.len == 0 and self.removed.len == 0 and self.changed.len == 0;
    }

    pub fn toTextAlloc(self: *const ManifestDiffResult, allocator: std.mem.Allocator, mode: DiffMode, policy: DiffPolicy, filter: DiffFilter) ![]u8 {
        _ = mode; _ = filter;
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();

        try out.appendSlice("MANIFEST diff\n");
        const c = self.counts();
        try out.writer().print("  added: {d}\n  removed: {d}\n  changed: {d}\n", .{ c.added, c.removed, c.changed });
        if (policy.limit != 0) try out.writer().print("  limit: {d}\n", .{policy.limit});
        if (policy.fail_fast) try out.appendSlice("  failFast: true\n");
        try out.appendSlice("\n");

        for (self.added) |p| try out.writer().print("+ {s}\n", .{p});
        for (self.removed) |p| try out.writer().print("- {s}\n", .{p});
        for (self.changed) |ch| {
            if (ch.from != null and ch.to != null) {
                try out.writer().print("~ {s} {s} {s} -> {s}\n", .{ ch.path, ch.reason, ch.from.?, ch.to.? });
            } else {
                try out.writer().print("~ {s} {s}\n", .{ ch.path, ch.reason });
            }
        }
        return out.toOwnedSlice();
    }

    pub fn toJsonAlloc(self: *const ManifestDiffResult, allocator: std.mem.Allocator, mode: DiffMode, policy: DiffPolicy, filter: DiffFilter) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var root = std.json.ObjectMap.init(a);
        try root.put("type", .{ .string = "manifestDiff" });

        var mode_obj = std.json.ObjectMap.init(a);
        try mode_obj.put("contentOnly", .{ .bool = mode.content_only });
        try root.put("mode", .{ .object = mode_obj });

        var policy_obj = std.json.ObjectMap.init(a);
        try policy_obj.put("limit", .{ .integer = @intCast(policy.limit) });
        try policy_obj.put("failFast", .{ .bool = policy.fail_fast });
        try root.put("policy", .{ .object = policy_obj });

        var filter_obj = std.json.ObjectMap.init(a);
        try filter_obj.put("pathsFrom", .{ .bool = filter.paths_from != null });
        try filter_obj.put("exclude", .{ .bool = (filter.exclude_from != null or filter.exclude_globs.len != 0) });
        try root.put("filter", .{ .object = filter_obj });

        var added_arr = std.json.Array.init(a);
        for (self.added) |p| try added_arr.append(.{ .string = p });
        try root.put("added", .{ .array = added_arr });

        var removed_arr = std.json.Array.init(a);
        for (self.removed) |p| try removed_arr.append(.{ .string = p });
        try root.put("removed", .{ .array = removed_arr });

        var changed_arr = std.json.Array.init(a);
        for (self.changed) |ch| {
            var o = std.json.ObjectMap.init(a);
            try o.put("path", .{ .string = ch.path });
            try o.put("reason", .{ .string = ch.reason });
            if (ch.from) |f| try o.put("from", .{ .string = f });
            if (ch.to) |t| try o.put("to", .{ .string = t });
            try changed_arr.append(.{ .object = o });
        }
        try root.put("changed", .{ .array = changed_arr });

        const c = self.counts();
        var counts_obj = std.json.ObjectMap.init(a);
        try counts_obj.put("added", .{ .integer = @intCast(c.added) });
        try counts_obj.put("removed", .{ .integer = @intCast(c.removed) });
        try counts_obj.put("changed", .{ .integer = @intCast(c.changed) });
        try root.put("counts", .{ .object = counts_obj });

        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try std.json.stringify(.{ .object = root }, .{ .whitespace = .minified }, buf.writer());
        return buf.toOwnedSlice();
    }
};

fn dupStr(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    return allocator.dupe(u8, s);
}

fn reachedLimit(policy: DiffPolicy, a: usize, r: usize, c: usize) bool {
    if (policy.limit == 0) return false;
    return (a + r + c) >= policy.limit;
}

fn entryEqualWithMode(a: ManifestEntry, b: ManifestEntry, mode: DiffMode) bool {
    if (!std.mem.eql(u8, a.kind, b.kind)) return false;

    if (mode.content_only) {
        if (std.mem.eql(u8, a.kind, "file")) {
            if (a.size != b.size) return false;
            if ((a.sha256 == null) != (b.sha256 == null)) return false;
            if (a.sha256) |as| {
                if (!std.mem.eql(u8, as, b.sha256.?)) return false;
            }
            return true;
        }
        if (std.mem.eql(u8, a.kind, "symlink")) {
            if ((a.target == null) != (b.target == null)) return false;
            if (a.target) |at| {
                if (!std.mem.eql(u8, at, b.target.?)) return false;
            }
            return true;
        }
        return true;
    }

    if (a.mode != b.mode) return false;
    if (a.uid != b.uid) return false;
    if (a.gid != b.gid) return false;
    if (a.mtime != b.mtime) return false;
    if (a.size != b.size) return false;

    if ((a.sha256 == null) != (b.sha256 == null)) return false;
    if (a.sha256) |as| if (!std.mem.eql(u8, as, b.sha256.?)) return false;

    if ((a.target == null) != (b.target == null)) return false;
    if (a.target) |at| if (!std.mem.eql(u8, at, b.target.?)) return false;

    return true;
}

fn isHexLower(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
}

fn validateSha256Hex(s: []const u8) !void {
    if (s.len != 64) return error.BadManifestJson;
    for (s) |c| {
        if (!isHexLower(c)) return error.BadManifestJson;
    }
}

fn validateKind(kind: []const u8) !void {
    if (std.mem.eql(u8, kind, "file")) return;
    if (std.mem.eql(u8, kind, "dir")) return;
    if (std.mem.eql(u8, kind, "symlink")) return;
    return error.BadManifestJson;
}

fn parseManifestToMap(allocator: std.mem.Allocator, bytes: []const u8) !std.StringHashMap(ManifestEntry) {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    errdefer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.BadManifestJson;

    const entries_val = root.object.get("entries") orelse return error.BadManifestJson;
    if (entries_val != .array) return error.BadManifestJson;

    var map = std.StringHashMap(ManifestEntry).init(allocator);
    errdefer {
        var it = map.iterator();
        while (it.next()) |kv| {
            allocator.free(kv.key_ptr.*);
            var v = kv.value_ptr.*;
            v.deinit(allocator);
        }
        map.deinit();
    }

    for (entries_val.array.items) |ev| {
        if (ev != .object) return error.BadManifestJson;

        const path_v = ev.object.get("path") orelse return error.BadManifestJson;
        const kind_v = ev.object.get("kind") orelse return error.BadManifestJson;
        if (path_v != .string or kind_v != .string) return error.BadManifestJson;

        const path = path_v.string;
        const kind = kind_v.string;

        if (path.len == 0) return error.BadManifestJson;
        try validateKind(kind);

        var me: ManifestEntry = .{ .kind = try allocator.dupe(u8, kind) };
        errdefer me.deinit(allocator);

        // Optional typed fields (reject wrong types if present)
        if (ev.object.get("mode")) |v| {
            if (v != .integer) return error.BadManifestJson;
            me.mode = @intCast(v.integer);
        }
        if (ev.object.get("uid")) |v| {
            if (v != .integer) return error.BadManifestJson;
            me.uid = @intCast(v.integer);
        }
        if (ev.object.get("gid")) |v| {
            if (v != .integer) return error.BadManifestJson;
            me.gid = @intCast(v.integer);
        }
        if (ev.object.get("mtime")) |v| {
            if (v != .integer) return error.BadManifestJson;
            me.mtime = @intCast(v.integer);
        }
        if (ev.object.get("size")) |v| {
            if (v != .integer) return error.BadManifestJson;
            if (v.integer < 0) return error.BadManifestJson;
            me.size = @intCast(v.integer);
        }

        if (ev.object.get("sha256")) |v| {
            if (v != .string) return error.BadManifestJson;
            try validateSha256Hex(v.string);
            me.sha256 = try allocator.dupe(u8, v.string);
        }
        if (ev.object.get("target")) |v| {
            if (v != .string) return error.BadManifestJson;
            me.target = try allocator.dupe(u8, v.string);
        }

        // Kind-specific requirements
        if (std.mem.eql(u8, kind, "file")) {
            // sha256 is optional, but if present must be valid (already validated)
        } else if (std.mem.eql(u8, kind, "dir")) {
            // no requirements
        } else if (std.mem.eql(u8, kind, "symlink")) {
            if (me.target == null) return error.BadManifestJson;
        }

        const k = try dupStr(allocator, path);
        // Disallow duplicates
        if (map.contains(k)) {
            allocator.free(k);
            me.deinit(allocator);
            return error.BadManifestJson;
        }
        try map.put(k, me);
    }

    parsed.deinit();
    return map;
}

fn freeManifestMap(allocator: std.mem.Allocator, map: *std.StringHashMap(ManifestEntry)) void {
    var it = map.iterator();
    while (it.next()) |kv| {
        allocator.free(kv.key_ptr.*);
        var v = kv.value_ptr.*;
        v.deinit(allocator);
    }
    map.deinit();
}

fn diffManifestResultAlloc(
    allocator: std.mem.Allocator,
    a_bytes: []const u8,
    b_bytes: []const u8,
    mode: DiffMode,
    policy: DiffPolicy,
    filter: DiffFilter,
) !ManifestDiffResult {
    _ = filter; // filtering is wired but not enforced in this minimal reference drop.

    var a_map = try parseManifestToMap(allocator, a_bytes);
    defer freeManifestMap(allocator, &a_map);

    var b_map = try parseManifestToMap(allocator, b_bytes);
    defer freeManifestMap(allocator, &b_map);

    var added = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (added.items) |p| allocator.free(p);
        added.deinit();
    }
    var removed = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (removed.items) |p| allocator.free(p);
        removed.deinit();
    }
    var changed = std.ArrayList(DiffChanged).init(allocator);
    errdefer {
        for (changed.items) |c| {
            allocator.free(c.path);
            allocator.free(c.reason);
            if (c.from) |f| allocator.free(f);
            if (c.to) |t| allocator.free(t);
        }
        changed.deinit();
    }

    // Removed + changed
    var itA = a_map.iterator();
    while (itA.next()) |kv| {
        if (policy.fail_fast and (added.items.len + removed.items.len + changed.items.len) > 0) break;

        const path = kv.key_ptr.*;
        const a_ent = kv.value_ptr.*;

        if (b_map.get(path)) |b_ent| {
            if (!entryEqualWithMode(a_ent.*, b_ent, mode)) {
                var ch: DiffChanged = undefined;

                if (a_ent.sha256 != null and b_ent.sha256 != null and !std.mem.eql(u8, a_ent.sha256.?, b_ent.sha256.?)) {
                    ch = .{
                        .path = try dupStr(allocator, path),
                        .reason = try dupStr(allocator, "sha256"),
                        .from = try dupStr(allocator, a_ent.sha256.?),
                        .to = try dupStr(allocator, b_ent.sha256.?),
                    };
                } else if (a_ent.target != null and b_ent.target != null and !std.mem.eql(u8, a_ent.target.?, b_ent.target.?)) {
                    ch = .{
                        .path = try dupStr(allocator, path),
                        .reason = try dupStr(allocator, "target"),
                        .from = try dupStr(allocator, a_ent.target.?),
                        .to = try dupStr(allocator, b_ent.target.?),
                    };
                } else {
                    ch = .{
                        .path = try dupStr(allocator, path),
                        .reason = try dupStr(allocator, if (mode.content_only) "content" else "metadata"),
                    };
                }

                if (!reachedLimit(policy, added.items.len, removed.items.len, changed.items.len)) {
                    if (!(mode.content_only and std.mem.eql(u8, ch.reason, "metadata"))) {
                        try changed.append(ch);
                    } else {
                        allocator.free(ch.path);
                        allocator.free(ch.reason);
                        if (ch.from) |f| allocator.free(f);
                        if (ch.to) |t| allocator.free(t);
                    }
                } else {
                    allocator.free(ch.path);
                    allocator.free(ch.reason);
                    if (ch.from) |f| allocator.free(f);
                    if (ch.to) |t| allocator.free(t);
                }
            }
        } else {
            if (!reachedLimit(policy, added.items.len, removed.items.len, changed.items.len)) {
                try removed.append(try dupStr(allocator, path));
            }
        }
    }

    // Added
    var itB = b_map.iterator();
    while (itB.next()) |kv| {
        if (policy.fail_fast and (added.items.len + removed.items.len + changed.items.len) > 0) break;

        const path = kv.key_ptr.*;
        if (!a_map.contains(path)) {
            if (!reachedLimit(policy, added.items.len, removed.items.len, changed.items.len)) {
                try added.append(try dupStr(allocator, path));
            }
        }
    }

    std.sort.block([]const u8, added.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool { return std.mem.lessThan(u8, a, b); }
    }.less);
    std.sort.block([]const u8, removed.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool { return std.mem.lessThan(u8, a, b); }
    }.less);
    std.sort.block(DiffChanged, changed.items, {}, struct {
        fn less(_: void, a: DiffChanged, b: DiffChanged) bool { return std.mem.lessThan(u8, a.path, b.path); }
    }.less);

    return .{
        .added = try added.toOwnedSlice(),
        .removed = try removed.toOwnedSlice(),
        .changed = try changed.toOwnedSlice(),
    };
}

pub const HashInfo = struct {
    alg: []const u8,
    hex: []const u8,
    length: u64,
};

pub const SectionHashInfo = struct {
    payload: ?HashInfo = null,
    meta: ?HashInfo = null,
    meta_bin: ?HashInfo = null,
    manifest: ?HashInfo = null,
    sig: ?HashInfo = null,

    pub fn deinit(self: *const SectionHashInfo, allocator: std.mem.Allocator) void {
        if (self.payload) |p| { allocator.free(p.alg); allocator.free(p.hex); }
        if (self.meta) |m0| { allocator.free(m0.alg); allocator.free(m0.hex); }
        if (self.meta_bin) |m1| { allocator.free(m1.alg); allocator.free(m1.hex); }
        if (self.manifest) |m2| { allocator.free(m2.alg); allocator.free(m2.hex); }
        if (self.sig) |s0| { allocator.free(s0.alg); allocator.free(s0.hex); }
    }
};

fn hashAlgName(alg: HashAlg) []const u8 {
    return switch (alg) {
        .sha256 => "sha256",
        .none => "none",
    };
}

fn bytesToHexAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const hexd = "0123456789abcdef";
    var out = try allocator.alloc(u8, bytes.len * 2);
    var j: usize = 0;
    for (bytes) |b| {
        out[j] = hexd[(b >> 4) & 0xF]; j += 1;
        out[j] = hexd[b & 0xF]; j += 1;
    }
    return out;
}

fn sectionHashInfoFromSectionAlloc(allocator: std.mem.Allocator, s: Section) !HashInfo {
    const alg: HashAlg = @enumFromInt(s.hash_alg);
    const alg_name = try allocator.dupe(u8, hashAlgName(alg));
    const hlen: usize = @intCast(s.hash_len);
    const hex = try bytesToHexAlloc(allocator, s.hash[0..hlen]);
    return .{ .alg = alg_name, .hex = hex, .length = s.length };
}

pub fn readSectionHashInfoAlloc(allocator: std.mem.Allocator, odi_path: []const u8) !SectionHashInfo {
    var file = try std.fs.cwd().openFile(odi_path, .{ .mode = .read_only });
    defer file.close();

    const st = try file.stat();
    const file_len: u64 = @intCast(st.size);

    var of = try OdiFile.readFromFile(allocator, file);
    defer of.deinit(allocator);

    try of.validateStructure(file_len);

    var info = SectionHashInfo{};
    errdefer info.deinit(allocator);

    if (of.findSection(.payload)) |s| info.payload = try sectionHashInfoFromSectionAlloc(allocator, s);
    if (of.findSection(.meta)) |s| info.meta = try sectionHashInfoFromSectionAlloc(allocator, s);
    if (of.findSection(.manifest)) |s| info.manifest = try sectionHashInfoFromSectionAlloc(allocator, s);

    return info;
}

pub fn writeSectionHashInfoText(writer: anytype, info: SectionHashInfo) !void {
    if (info.payload) |p| {
        try writer.print("payload:  {s}:{s}  {d} bytes\n", .{ p.alg, p.hex, p.length });
    } else try writer.writeAll("payload:  (missing)\n");

    if (info.meta) |m| {
        try writer.print("meta:     {s}:{s}  {d} bytes\n", .{ m.alg, m.hex, m.length });
    } else try writer.writeAll("meta:     (missing)\n");

    if (info.manifest) |m| {
        try writer.print("manifest: {s}:{s}  {d} bytes\n", .{ m.alg, m.hex, m.length });
    } else try writer.writeAll("manifest: (missing)\n");
}

pub fn sectionHashInfoToJsonAlloc(allocator: std.mem.Allocator, odi_path: []const u8, info: SectionHashInfo) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var root = std.json.ObjectMap.init(a);
    try root.put("type", .{ .string = "manifestHash" });
    try root.put("file", .{ .string = odi_path });

    if (info.payload) |p| {
        var o = std.json.ObjectMap.init(a);
        try o.put("alg", .{ .string = p.alg });
        try o.put("hash", .{ .string = p.hex });
        try o.put("length", .{ .integer = @intCast(p.length) });
        try root.put("payload", .{ .object = o });
    }

    if (info.meta) |m| {
        var o = std.json.ObjectMap.init(a);
        try o.put("alg", .{ .string = m.alg });
        try o.put("hash", .{ .string = m.hex });
        try o.put("length", .{ .integer = @intCast(m.length) });
        try root.put("meta", .{ .object = o });
    }

    if (info.manifest) |m| {
        var o = std.json.ObjectMap.init(a);
        try o.put("alg", .{ .string = m.alg });
        try o.put("hash", .{ .string = m.hex });
        try o.put("length", .{ .integer = @intCast(m.length) });
        try root.put("manifest", .{ .object = o });
    }

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try std.json.stringify(.{ .object = root }, .{ .whitespace = .minified }, buf.writer());
    return buf.toOwnedSlice();
}

// Attestation (minimal): based on section table. Signature status optional.
pub const Attestation = struct {
    hashes: SectionHashInfo,
    signature_present: bool = false,
    signature_verified: bool = false,
    signature_principal: ?[]const u8 = null,

    pub fn deinit(self: *Attestation, allocator: std.mem.Allocator) void {
        self.hashes.deinit(allocator);
        if (self.signature_principal) |p| allocator.free(p);
    }

    pub fn toLineAlloc(self: *const Attestation, allocator: std.mem.Allocator) ![]u8 {
        const payload = try fmtHashKV(allocator, "payload", self.hashes.payload);
        defer allocator.free(payload);
        const manifest = try fmtHashKV(allocator, "manifest", self.hashes.manifest);
        defer allocator.free(manifest);
        const meta = try fmtHashKV(allocator, "meta", self.hashes.meta);
        defer allocator.free(meta);

        var sig_part: []u8 = undefined;
        if (!self.signature_present) {
            sig_part = try allocator.dupe(u8, "sig=none");
        } else if (self.signature_verified and self.signature_principal != null) {
            sig_part = try std.fmt.allocPrint(allocator, "sig=ssh:principal:{s}", .{self.signature_principal.?});
        } else {
            sig_part = try allocator.dupe(u8, "sig=present");
        }
        defer allocator.free(sig_part);

        return std.fmt.allocPrint(allocator, "ODI attest {s} {s} {s} {s}", .{ payload, manifest, meta, sig_part });
    }

    pub fn toJsonAlloc(self: *const Attestation, allocator: std.mem.Allocator) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var root = std.json.ObjectMap.init(a);
        try root.put("type", .{ .string = "attest" });

        if (self.hashes.payload) |p| {
            var o = std.json.ObjectMap.init(a);
            try o.put("alg", .{ .string = p.alg });
            try o.put("hash", .{ .string = p.hex });
            try o.put("length", .{ .integer = @intCast(p.length) });
            try root.put("payload", .{ .object = o });
        }
        if (self.hashes.manifest) |p| {
            var o = std.json.ObjectMap.init(a);
            try o.put("alg", .{ .string = p.alg });
            try o.put("hash", .{ .string = p.hex });
            try o.put("length", .{ .integer = @intCast(p.length) });
            try root.put("manifest", .{ .object = o });
        }
        if (self.hashes.meta) |p| {
            var o = std.json.ObjectMap.init(a);
            try o.put("alg", .{ .string = p.alg });
            try o.put("hash", .{ .string = p.hex });
            try o.put("length", .{ .integer = @intCast(p.length) });
            try root.put("meta", .{ .object = o });
        }

        var s = std.json.ObjectMap.init(a);
        try s.put("present", .{ .bool = self.signature_present });
        try s.put("verified", .{ .bool = self.signature_verified });
        var bound = std.json.ObjectMap.init(a);
        try bound.put("payload", .{ .bool = self.sig_bound_payload });
        try bound.put("meta", .{ .bool = self.sig_bound_meta });
        try bound.put("meta_bin", .{ .bool = self.sig_bound_meta_bin });
        try bound.put("manifest", .{ .bool = self.sig_bound_manifest });
        try s.put("bound", .{ .object = bound });
        try s.put("binds_meta_bin_ok", .{ .bool = self.sig_binds_meta_bin_ok });
        if (self.signature_principal) |p| try s.put("principal", .{ .string = p });
        try root.put("signature", .{ .object = s });

        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try std.json.stringify(.{ .object = root }, .{ .whitespace = .minified }, buf.writer());
        return buf.toOwnedSlice();
    }
};

fn fmtHashKV(allocator: std.mem.Allocator, label: []const u8, hi: ?HashInfo) ![]u8 {
    if (hi == null) return std.fmt.allocPrint(allocator, "{s}=missing", .{label});
    return std.fmt.allocPrint(allocator, "{s}={s}:{s}", .{ label, hi.?.alg, hi.?.hex });
}

pub fn attestFromFileAlloc(
    allocator: std.mem.Allocator,
    odi_path: []const u8,
    verify: bool,
    sig_check: ?SignatureCheck,
) !Attestation {
    var file = try std.fs.cwd().openFile(odi_path, .{ .mode = .read_only });
    defer file.close();

    const st = try file.stat();
    const file_len: u64 = @intCast(st.size);

    var of = try OdiFile.readFromFile(allocator, file);
    defer of.deinit(allocator);
    try of.validateStructure(file_len);

    if (verify) try of.verifySectionHashes(file);

    var att: Attestation = .{
        .hashes = try sectionHashInfoFromOdiFileAlloc(allocator, &of),
        .signature_present = (of.findSection(.sig) != null),
        .signature_verified = false,
        .signature_principal = null,
    };
    errdefer att.deinit(allocator);

    if (sig_check) |sc| {
        if (att.signature_present) {
            try verifySignatureWithSshKeygen(.{
                .allocator = allocator,
                .file = file,
                .of = &of,
                .allowed_signers_path = sc.allowed_signers,
                .identity = sc.identity,
                .ssh_keygen_path = sc.ssh_keygen_path,
            });
            att.signature_verified = true;
            att.signature_principal = try allocator.dupe(u8, sc.identity);
        } else if (sc.require_signature) {
            return error.MissingSignature;
        }
    }

    return att;
}

pub fn sectionHashInfoFromOdiFileAlloc(allocator: std.mem.Allocator, of: *const OdiFile) !SectionHashInfo {
    var info = SectionHashInfo{};
    errdefer info.deinit(allocator);

    if (of.findSection(.payload)) |s| info.payload = try sectionHashInfoFromSectionAlloc(allocator, s);
    if (of.findSection(.meta)) |s| info.meta = try sectionHashInfoFromSectionAlloc(allocator, s);
    if (of.findSection(.manifest)) |s| info.manifest = try sectionHashInfoFromSectionAlloc(allocator, s);

    return info;
}

// ---- verify report ----

pub const VerifyOptions = struct {
    allocator: std.mem.Allocator,
    odi_path: []const u8,
    verify_hashes: bool = false,
    require_manifest: bool = false,
    require_meta_bin: bool = false,
    require_signature: bool = false,
    require_sig_binds_meta_bin: bool = false,
    allowed_signers: ?[]const u8 = null,
    identity: ?[]const u8 = null,
    ssh_keygen_path: []const u8 = "ssh-keygen",
};

pub const VerifyReport = struct {
    ok: bool,
    file_ok: bool,
    hashes_ok: bool,
    manifest_present: bool,
    meta_present: bool,
    meta_bin_present: bool,
    signature_present: bool,
    sig_bound_payload: bool = false,
    sig_bound_meta: bool = false,
    sig_bound_meta_bin: bool = false,
    sig_bound_manifest: bool = false,
    sig_binds_meta_bin_ok: bool = true,
    signature_verified: bool,
    signature_required: bool,
    signature_principal: ?[]const u8 = null,
    err_name: ?[]const u8 = null,

    pub fn deinit(self: *VerifyReport, allocator: std.mem.Allocator) void {
        if (self.signature_principal) |p| allocator.free(p);
        if (self.err_name) |e| allocator.free(e);
    }

    pub fn toTextAlloc(self: *const VerifyReport, allocator: std.mem.Allocator) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();

        try out.appendSlice("ODI verify\n");
        try out.writer().print("  fileOk: {s}\n", .{if (self.file_ok) "true" else "false"});
        try out.writer().print("  hashesOk: {s}\n", .{if (self.hashes_ok) "true" else "false"});
        try out.writer().print("  manifestPresent: {s}\n", .{if (self.manifest_present) "true" else "false"});
        try out.writer().print("  metaPresent: {s}\n", .{if (self.meta_present) "true" else "false"});
        try out.writer().print("  metaBinPresent: {s}\n", .{if (self.meta_bin_present) "true" else "false"});
        try out.writer().print("  signaturePresent: {s}\n", .{if (self.signature_present) "true" else "false"});
        try out.writer().print("  signatureRequired: {s}\n", .{if (self.signature_required) "true" else "false"});
        try out.writer().print("  signatureVerified: {s}\n", .{if (self.signature_verified) "true" else "false"});
        if (self.signature_present) {
            try out.writer().print("  sigBindsMetaBinOk: {s}\n", .{if (self.sig_binds_meta_bin_ok) "true" else "false"});
            try out.appendSlice("  signatureBound:");
            if (self.sig_bound_payload) try out.appendSlice(" payload");
            if (self.sig_bound_meta) try out.appendSlice(" meta");
            if (self.sig_bound_meta_bin) try out.appendSlice(" meta_bin");
            if (self.sig_bound_manifest) try out.appendSlice(" manifest");
            try out.append('\n');
        }
        if (self.signature_principal) |p| try out.writer().print("  principal: {s}\n", .{p});
        if (self.err_name) |e| try out.writer().print("  error: {s}\n", .{e});
        try out.writer().print("  ok: {s}\n", .{if (self.ok) "true" else "false"});
        return out.toOwnedSlice();
    }

    pub fn toJsonAlloc(self: *const VerifyReport, allocator: std.mem.Allocator) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var root = std.json.ObjectMap.init(a);
        try root.put("type", .{ .string = "verify" });
        try root.put("ok", .{ .bool = self.ok });
        try root.put("fileOk", .{ .bool = self.file_ok });
        try root.put("hashesOk", .{ .bool = self.hashes_ok });
        try root.put("manifestPresent", .{ .bool = self.manifest_present });
        try root.put("metaPresent", .{ .bool = self.meta_present });
        try root.put("metaBinPresent", .{ .bool = self.meta_bin_present });

        var s = std.json.ObjectMap.init(a);
        try s.put("present", .{ .bool = self.signature_present });
        try s.put("required", .{ .bool = self.signature_required });
        try s.put("verified", .{ .bool = self.signature_verified });
        var bound = std.json.ObjectMap.init(a);
        try bound.put("payload", .{ .bool = self.sig_bound_payload });
        try bound.put("meta", .{ .bool = self.sig_bound_meta });
        try bound.put("meta_bin", .{ .bool = self.sig_bound_meta_bin });
        try bound.put("manifest", .{ .bool = self.sig_bound_manifest });
        try s.put("bound", .{ .object = bound });
        try s.put("binds_meta_bin_ok", .{ .bool = self.sig_binds_meta_bin_ok });
        if (self.signature_principal) |p| try s.put("principal", .{ .string = p });
        try root.put("signature", .{ .object = s });

        if (self.err_name) |e| try root.put("error", .{ .string = e });

        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try std.json.stringify(.{ .object = root }, .{ .whitespace = .minified }, buf.writer());
        return buf.toOwnedSlice();
    }
};

pub fn verifyFileAlloc(opts: VerifyOptions) !VerifyReport {
    var r: VerifyReport = .{
        .ok = false,
        .file_ok = false,
        .hashes_ok = false,
        .manifest_present = false,
        .meta_present = false,
        .meta_bin_present = false,
        .signature_present = false,
        .signature_verified = false,
        .signature_required = opts.require_signature,
        .signature_principal = null,
        .err_name = null,
    };
    errdefer r.deinit(opts.allocator);

    var file = std.fs.cwd().openFile(opts.odi_path, .{ .mode = .read_only }) catch |e| {
        r.err_name = try opts.allocator.dupe(u8, @errorName(e));
        return r;
    };
    defer file.close();

    const st = file.stat() catch |e| {
        r.err_name = try opts.allocator.dupe(u8, @errorName(e));
        return r;
    };
    const file_len: u64 = @intCast(st.size);

    var of = OdiFile.readFromFile(opts.allocator, file) catch |e| {
        r.err_name = try opts.allocator.dupe(u8, @errorName(e));
        return r;
    };
    defer of.deinit(opts.allocator);

    of.validateStructure(file_len) catch |e| {
        r.err_name = try opts.allocator.dupe(u8, @errorName(e));
        return r;
    };

    r.file_ok = true;

    // Section presence
    r.meta_present = (of.findSection(.meta) != null);
    r.meta_bin_present = (of.findSection(.meta_bin) != null);

    if (opts.require_meta_bin and !r.meta_bin_present) {
        r.err_name = try opts.allocator.dupe(u8, "MissingMetaBin");
        return r;
    }


    r.manifest_present = (of.findSection(.manifest) != null);
    if (opts.require_manifest and !r.manifest_present) {
        r.err_name = try opts.allocator.dupe(u8, "MissingManifest");
        r.ok = false;
        return r;
    }

    r.signature_present = (of.findSection(.sig) != null);
    if (opts.require_signature and !r.signature_present) {
        r.err_name = try opts.allocator.dupe(u8, "MissingSignature");
        r.ok = false;
        return r;
    }

    if (opts.verify_hashes) {
        of.verifySectionHashes(file) catch |e| {
            r.err_name = try opts.allocator.dupe(u8, @errorName(e));
            return r;
        };
        r.hashes_ok = true;
    }

    if (opts.require_signature or (opts.allowed_signers != null and opts.identity != null)) {
        if (opts.allowed_signers == null or opts.identity == null) {
            r.err_name = try opts.allocator.dupe(u8, "MissingSignatureArgs");
            return r;
        }
        if (!r.signature_present) {
            r.err_name = try opts.allocator.dupe(u8, "MissingSignature");
            return r;
        }
        verifySignatureWithSshKeygen(.{
            .allocator = opts.allocator,
            .file = file,
            .of = &of,
            .allowed_signers_path = opts.allowed_signers.?,
            .identity = opts.identity.?,
            .ssh_keygen_path = opts.ssh_keygen_path,
        }) catch |e| {
            r.err_name = try opts.allocator.dupe(u8, @errorName(e));
            return r;
        };
        r.signature_verified = true;
        // Optional strict mode: require that the signature binds meta_bin (and meta_bin exists).
        if (opts.require_sig_binds_meta_bin) {
            if (!r.meta_bin_present) {
                r.sig_binds_meta_bin_ok = false;
                r.err_name = try opts.allocator.dupe(u8, "MissingMetaBin");
                return r;
            }
            if (!r.sig_bound_meta_bin) {
                r.sig_binds_meta_bin_ok = false;
                r.err_name = try opts.allocator.dupe(u8, "SignatureDoesNotBindMetaBin");
                return r;
            }
        }

        r.signature_principal = try opts.allocator.dupe(u8, opts.identity.?);
    }

    r.ok = r.file_ok and (!opts.verify_hashes or r.hashes_ok) and (!opts.require_manifest or r.manifest_present) and (!opts.require_signature or r.signature_verified);
    return r;
}

// ---- signing ----

pub const SignatureCheck = struct {
    require_signature: bool,
    allowed_signers: []const u8,
    identity: []const u8,
    ssh_keygen_path: []const u8 = "ssh-keygen",
};

pub const SignOptions = struct {
    allocator: std.mem.Allocator,
    in_path: []const u8,
    out_path: []const u8,
    key_path: []const u8,
    identity: []const u8,
    ssh_keygen_path: []const u8 = "ssh-keygen",
    strip_existing_sig: bool = true,
    verify_before_sign: bool = true,
};

pub fn buildSigPayloadAlloc(allocator: std.mem.Allocator, hashes: SectionHashInfo) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    // Stable signing payload that binds to section hashes.
    // Presence is explicit: missing sections are omitted.
    //
    // Format:
    //   ODI-SIG-V1\n
    //   <name> <alg> <hex>\n
    //
    // Names are fixed and ordered.
    try out.appendSlice("ODI-SIG-V1\n");

    try appendSigLine(out.writer(), "payload", hashes.payload);
    try appendSigLine(out.writer(), "meta", hashes.meta);
    try appendSigLine(out.writer(), "meta_bin", hashes.meta_bin);
    try appendSigLine(out.writer(), "manifest", hashes.manifest);

    return out.toOwnedSlice();
}

fn appendSigLine(w: anytype, label: []const u8, hi: ?HashInfo) !void {
    if (hi == null) {
        try w.print("{s} missing\n", .{label});
        return;
    }
    try w.print("{s} {s} {s}\n", .{ label, hi.?.alg, hi.?.hex });
}

fn makeTempPathAlloc(allocator: std.mem.Allocator, prefix: []const u8) ![]u8 {
    var prng = std.rand.DefaultPrng.init(@intCast(std.time.nanoTimestamp()));
    const x = prng.random().int(u64);
    return std.fmt.allocPrint(allocator, "{s}{x}.tmp", .{ prefix, x });
}

fn runCommand(argv: []const []const u8) !bool {
    var child = std.process.Child.init(argv, std.heap.page_allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    const term = try child.spawnAndWait();
    return term == .Exited and term.Exited == 0;
}

fn runCommandOrFail(argv: []const []const u8) !void {
    const ok = try runCommand(argv);
    if (!ok) return error.CommandFailed;
}

fn sshKeygenSignAlloc(
    allocator: std.mem.Allocator,
    ssh_keygen_path: []const u8,
    key_path: []const u8,
    identity: []const u8,
    namespace: []const u8,
    data_path: []const u8,
) ![]u8 {
    const argv1 = &[_][]const u8{
        ssh_keygen_path, "-Y", "sign",
        "-f", key_path,
        "-I", identity,
        "-n", namespace,
        data_path,
    };
    const ok1 = try runCommand(argv1);
    if (!ok1) {
        const argv2 = &[_][]const u8{
            ssh_keygen_path, "-Y", "sign",
            "-f", key_path,
            "-n", namespace,
            data_path,
        };
        try runCommandOrFail(argv2);
    }

    const sig_path = try std.fmt.allocPrint(allocator, "{s}.sig", .{data_path});
    defer allocator.free(sig_path);
    return try readFileAlloc(allocator, sig_path, 16 * 1024 * 1024);
}

fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8, max: usize) ![]u8 {
    var f = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
    defer f.close();
    const st = try f.stat();
    if (st.size > max) return error.FileTooLarge;
    const n: usize = @intCast(st.size);
    const buf = try allocator.alloc(u8, n);
    errdefer allocator.free(buf);
    try f.reader().readNoEof(buf);
    return buf;
}

pub fn verifySignatureWithSshKeygen(opts: struct {
    allocator: std.mem.Allocator,
    file: std.fs.File,
    of: *const OdiFile,
    allowed_signers_path: []const u8,
    identity: []const u8,
    ssh_keygen_path: []const u8 = "ssh-keygen",
}) !void {
    const hashes = try sectionHashInfoFromOdiFileAlloc(opts.allocator, opts.of);
    defer hashes.deinit(opts.allocator);

    const payload = try buildSigPayloadAlloc(opts.allocator, hashes);
    defer opts.allocator.free(payload);

    const ss = opts.of.findSection(.sig) orelse return error.MissingSignature;
    const sig_bytes = try readSectionAlloc(opts.allocator, opts.file, ss.offset, ss.length, 16 * 1024 * 1024);
    defer opts.allocator.free(sig_bytes);

    const data_path = try makeTempPathAlloc(opts.allocator, "odi_sigdata_");
    defer opts.allocator.free(data_path);
    const sig_path = try makeTempPathAlloc(opts.allocator, "odi_sig_");
    defer opts.allocator.free(sig_path);

    {
        var df = try std.fs.cwd().createFile(data_path, .{ .truncate = true });
        defer df.close();
        try df.writeAll(payload);
    }
    {
        var sf = try std.fs.cwd().createFile(sig_path, .{ .truncate = true });
        defer sf.close();
        try sf.writeAll(sig_bytes);
    }

    defer std.fs.cwd().deleteFile(data_path) catch {};
    defer std.fs.cwd().deleteFile(sig_path) catch {};

    const argv = &[_][]const u8{
        opts.ssh_keygen_path, "-Y", "verify",
        "-f", opts.allowed_signers_path,
        "-I", opts.identity,
        "-n", "odi",
        "-s", sig_path,
        data_path,
    };

    try runCommandOrFail(argv);
}

pub fn signOdiFile(opts: SignOptions) !void {
    var in_file = try std.fs.cwd().openFile(opts.in_path, .{ .mode = .read_only });
    defer in_file.close();

    const st = try in_file.stat();
    const file_len: u64 = @intCast(st.size);

    var of = try OdiFile.readFromFile(opts.allocator, in_file);
    defer of.deinit(opts.allocator);

    try of.validateStructure(file_len);
    if (opts.verify_before_sign) try of.verifySectionHashes(in_file);

    const hashes = try sectionHashInfoFromOdiFileAlloc(opts.allocator, &of);
    defer hashes.deinit(opts.allocator);

    const sig_payload = try buildSigPayloadAlloc(opts.allocator, hashes);
    defer opts.allocator.free(sig_payload);

    const data_path = try makeTempPathAlloc(opts.allocator, "odi_sign_");
    defer opts.allocator.free(data_path);

    const sig_path = try std.fmt.allocPrint(opts.allocator, "{s}.sig", .{data_path});
    defer opts.allocator.free(sig_path);

    {
        var df = try std.fs.cwd().createFile(data_path, .{ .truncate = true });
        defer df.close();
        try df.writeAll(sig_payload);
    }
    defer std.fs.cwd().deleteFile(data_path) catch {};
    defer std.fs.cwd().deleteFile(sig_path) catch {};

    const sig_bytes = try sshKeygenSignAlloc(opts.allocator, opts.ssh_keygen_path, opts.key_path, opts.identity, "odi", data_path);
    defer opts.allocator.free(sig_bytes);

    try rewriteOdiWithNewSig(.{
        .allocator = opts.allocator,
        .in_file = in_file,
        .in_of = &of,
        .out_path = opts.out_path,
        .sig_bytes = sig_bytes,
    });
}

const RewriteSigOptions = struct {
    allocator: std.mem.Allocator,
    in_file: std.fs.File,
    in_of: *const OdiFile,
    out_path: []const u8,
    sig_bytes: []const u8,
};

fn copySectionAndHash(
    in_file: std.fs.File,
    out_file: std.fs.File,
    in_off: u64,
    len: u64,
    hash_alg: HashAlg,
    stype: SectionType,
    cursor: *u64,
) !Section {
    const start = cursor.*;
    try in_file.seekTo(in_off);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var remaining: u64 = len;

    var buf: [1024 * 1024]u8 = undefined;
    while (remaining > 0) {
        const want: usize = @intCast(@min(remaining, buf.len));
        const got = try in_file.read(buf[0..want]);
        if (got == 0) return error.UnexpectedEof;

        try out_file.writeAll(buf[0..got]);
        hasher.update(buf[0..got]);

        remaining -= got;
        cursor.* += got;
    }

    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    var s: Section = undefined;
    s.stype = @intFromEnum(stype);
    s.reserved0 = 0;
    s.offset = start;
    s.length = len;
    s.hash_alg = @intFromEnum(hash_alg);
    s.hash_len = 32;
    s.reserved1 = 0;
    @memset(&s.hash, 0);
    @memcpy(s.hash[0..32], digest[0..]);

    return s;
}

fn writeBytesAndHash(
    out_file: std.fs.File,
    stype: SectionType,
    bytes: []const u8,
    hash_alg: HashAlg,
    cursor: *u64,
) !Section {
    const start = cursor.*;

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(bytes);

    try out_file.writeAll(bytes);
    cursor.* += bytes.len;

    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    var s: Section = undefined;
    s.stype = @intFromEnum(stype);
    s.reserved0 = 0;
    s.offset = start;
    s.length = @intCast(bytes.len);
    s.hash_alg = @intFromEnum(hash_alg);
    s.hash_len = 32;
    s.reserved1 = 0;
    @memset(&s.hash, 0);
    @memcpy(s.hash[0..32], digest[0..]);

    return s;
}

fn rewriteOdiWithNewSig(opts: RewriteSigOptions) !void {
    var out_file = try std.fs.cwd().createFile(opts.out_path, .{ .truncate = true, .read = true });
    defer out_file.close();

    const payload = opts.in_of.findSection(.payload) orelse return error.MissingPayload;
    const meta = opts.in_of.findSection(.meta);
    const manifest = opts.in_of.findSection(.manifest) orelse return error.MissingManifest;

    const header_size = @sizeOf(Header);
    const table_entry_size = @sizeOf(Section);

    var section_count: usize = 0;
    section_count += 1;
    if (meta != null) section_count += 1;
    section_count += 1;
    section_count += 1; // new sig

    const reserve: u64 = @intCast(header_size + table_entry_size * section_count);
    try out_file.seekTo(reserve);
    var cursor: u64 = reserve;

    var sections = std.ArrayList(Section).init(opts.allocator);
    defer sections.deinit();

    const payload_s = try copySectionAndHash(opts.in_file, out_file, payload.offset, payload.length, .sha256, .payload, &cursor);
    try sections.append(payload_s);

    if (meta) |ms| {
        const meta_s = try copySectionAndHash(opts.in_file, out_file, ms.offset, ms.length, .sha256, .meta, &cursor);
        try sections.append(meta_s);
    }

    const manifest_s = try copySectionAndHash(opts.in_file, out_file, manifest.offset, manifest.length, .sha256, .manifest, &cursor);
    try sections.append(manifest_s);

    const sig_s = try writeBytesAndHash(out_file, .sig, opts.sig_bytes, .sha256, &cursor);
    try sections.append(sig_s);

    try out_file.seekTo(0);
    var hdr = Header.initDefault();
    hdr.section_count = @intCast(sections.items.len);
    hdr.table_offset = header_size;
    hdr.table_length = @intCast(sections.items.len * @sizeOf(Section));

    try out_file.writeAll(std.mem.asBytes(&hdr));
    for (sections.items) |s| {
        try out_file.writeAll(std.mem.asBytes(&s));
    }
}


// ---- META ----

pub fn readMetaAlloc(allocator: std.mem.Allocator, odi_path: []const u8) ![]u8 {
    var file = try std.fs.cwd().openFile(odi_path, .{ .mode = .read_only });
    defer file.close();

    const st = try file.stat();
    const file_len: u64 = @intCast(st.size);

    var of = try OdiFile.readFromFile(allocator, file);
    defer of.deinit(allocator);

    try of.validateStructure(file_len);

    const ms = of.findSection(.meta) orelse return error.MissingMeta;
    return try readSectionAlloc(allocator, file, ms.offset, ms.length, 32 * 1024 * 1024);
}

pub fn readSigAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return try readSectionByTypeAlloc(allocator, path, .sig);
}

pub fn readMetaBinAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return try readSectionByTypeAlloc(allocator, path, .meta_bin);
}

pub fn readEffectiveMetaJsonAlloc(allocator: std.mem.Allocator, odi_path: []const u8) ![]u8 {
    // If meta_bin exists, project ODM to JSON for user-facing tooling.
    const mb = readMetaBinAlloc(allocator, odi_path) catch null;
    if (mb != null) {
        defer allocator.free(mb.?);
        const odm = @import("odm.zig");
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const root = try odm.decodeAlloc(arena.allocator(), mb.?, .{ .require_canonical = true });
        return try odmToJsonAlloc(allocator, root);
    }

    // Fallback to JSON meta.
    return try readMetaAlloc(allocator, odi_path);
}

pub fn metaPointerGetEffectiveAlloc(allocator: std.mem.Allocator, odi_path: []const u8, ptr: []const u8) ![]u8 {
    const meta_json = try readEffectiveMetaJsonAlloc(allocator, odi_path);
    defer allocator.free(meta_json);
    return try metaPointerGetAlloc(allocator, meta_json, ptr);
}



fn decodeJsonPointerTokenAlloc(allocator: std.mem.Allocator, token: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    var i: usize = 0;
    while (i < token.len) : (i += 1) {
        const c = token[i];
        if (c != '~') {
            try out.append(c);
            continue;
        }
        if (i + 1 >= token.len) return error.InvalidPointer;
        const n = token[i + 1];
        if (n == '0') try out.append('~')
        else if (n == '1') try out.append('/')
        else return error.InvalidPointer;
        i += 1;
    }
    return out.toOwnedSlice();
}

pub fn metaPointerGetAlloc(allocator: std.mem.Allocator, meta_bytes: []const u8, ptr: []const u8) ![]u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, meta_bytes, .{});
    defer parsed.deinit();

    var v = parsed.value;

    if (ptr.len == 0 or std.mem.eql(u8, ptr, "/")) {
        return try std.json.stringifyAlloc(allocator, v, .{ .whitespace = .minified });
    }
    if (ptr[0] != '/') return error.InvalidPointer;

    var it = std.mem.splitScalar(u8, ptr[1..], '/');
    while (it.next()) |raw| {
        const tok = try decodeJsonPointerTokenAlloc(allocator, raw);
        defer allocator.free(tok);

        if (v != .object) return error.PointerNotFound;
        const next = v.object.get(tok) orelse return error.PointerNotFound;
        v = next;
    }

    return try std.json.stringifyAlloc(allocator, v, .{ .whitespace = .minified });
}

pub fn metaPointerSetStringAlloc(allocator: std.mem.Allocator, meta_bytes: []const u8, ptr: []const u8, value: []const u8) ![]u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, meta_bytes, .{});
    defer parsed.deinit();

    var root = parsed.value;

    if (ptr.len == 0 or ptr[0] != '/') return error.InvalidPointer;

    var tokens = std.ArrayList([]u8).init(allocator);
    defer {
        for (tokens.items) |t| allocator.free(t);
        tokens.deinit();
    }

    var it = std.mem.splitScalar(u8, ptr[1..], '/');
    while (it.next()) |raw| try tokens.append(try decodeJsonPointerTokenAlloc(allocator, raw));
    if (tokens.items.len == 0) return error.InvalidPointer;

    var cur = &root;
    var idx: usize = 0;

    while (idx + 1 < tokens.items.len) : (idx += 1) {
        const key = tokens.items[idx];

        if (cur.* != .object) {
            cur.* = .{ .object = std.json.ObjectMap.init(allocator) };
        }

        const obj = &cur.*.object;
        if (obj.getPtr(key)) |next| {
            cur = next;
        } else {
            try obj.put(key, .{ .object = std.json.ObjectMap.init(allocator) });
            cur = obj.getPtr(key).?;
        }
    }

    const last = tokens.items[tokens.items.len - 1];
    if (cur.* != .object) cur.* = .{ .object = std.json.ObjectMap.init(allocator) };
    try cur.*.object.put(last, .{ .string = value });

    return try std.json.stringifyAlloc(allocator, root, .{ .whitespace = .minified });
}

fn canonicalizeJsonBytesAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = try std.json.parseFromSlice(std.json.Value, a, bytes, .{});
    // parsed memory is arena-owned; no need to deinit explicitly.
    return try canonicalJsonAlloc(allocator, a, parsed.value);
}

pub fn canonicalizeMetaAlloc(allocator: std.mem.Allocator, meta_bytes: []const u8) ![]u8 {
    return try canonicalizeJsonBytesAlloc(allocator, meta_bytes);
}

fn canonicalJsonAlloc(allocator_out: std.mem.Allocator, allocator_tmp: std.mem.Allocator, v: std.json.Value) ![]u8 {
    var out = std.ArrayList(u8).init(allocator_out);
    errdefer out.deinit();
    try canonicalWriteValue(out.writer(), allocator_tmp, v);
    return out.toOwnedSlice();
}

fn canonicalWriteValue(w: anytype, allocator_tmp: std.mem.Allocator, v: std.json.Value) !void {
    switch (v) {
        .null => try w.writeAll("null"),
        .bool => |b| if (b) try w.writeAll("true") else try w.writeAll("false"),
        .string => |s| try writeJsonString(w, s),
        .integer => |i| try w.print("{d}", .{i}),
        .float => |f| {
            // 17 digits is enough to round-trip f64
            var buf: [64]u8 = undefined;
            const s = try std.fmt.bufPrint(&buf, "{d:.17}", .{f});
            // Normalize "-0.000..." to "0" where applicable
            if (std.mem.eql(u8, s, "-0") or std.mem.startsWith(u8, s, "-0.")) {
                var s2 = s[1..];
                // strip trailing zeros
                s2 = stripFloatTrailingZeros(s2);
                try w.writeAll(s2);
            } else {
                const s2 = stripFloatTrailingZeros(s);
                try w.writeAll(s2);
            }
        },
        .array => |a| {
            try w.writeByte('[');
            for (a.items, 0..) |item, idx| {
                if (idx != 0) try w.writeByte(',');
                try canonicalWriteValue(w, allocator_tmp, item);
            }
            try w.writeByte(']');
        },
        .object => |o| {
            // sort keys lexicographically for canonical output
            var keys = std.ArrayList([]const u8).init(allocator_tmp);
            defer keys.deinit();

            var it = o.iterator();
            while (it.next()) |kv| try keys.append(kv.key_ptr.*);

            std.sort.block([]const u8, keys.items, {}, struct {
                fn less(_: void, a: []const u8, b: []const u8) bool {
                    return std.mem.lessThan(u8, a, b);
                }
            }.less);

            try w.writeByte('{');
            for (keys.items, 0..) |k, idx| {
                if (idx != 0) try w.writeByte(',');
                try writeJsonString(w, k);
                try w.writeByte(':');
                const val = o.get(k).?;
                try canonicalWriteValue(w, allocator_tmp, val);
            }
            try w.writeByte('}');
        },
    }
}

fn stripFloatTrailingZeros(s: []const u8) []const u8 {
    // If no '.', nothing to do
    const dot = std.mem.indexOfScalar(u8, s, '.') orelse return s;
    var end: usize = s.len;

    // strip trailing zeros
    while (end > dot + 1 and s[end - 1] == '0') : (end -= 1) {}
    // strip trailing '.' if becomes integer
    if (end == dot + 1) end = dot;
    return s[0..end];
}

fn writeJsonString(w: anytype, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0x08 => try w.writeAll("\\b"),
            0x0C => try w.writeAll("\\f"),
            else => {
                if (c < 0x20) {
                    var buf: [6]u8 = undefined;
                    _ = try std.fmt.bufPrint(&buf, "\\u00{x:0>2}", .{c});
                    try w.writeAll(buf[0..6]);
                } else {
                    try w.writeByte(c);
                }
            },
        }
    }
    try w.writeByte('"');
}

pub fn metaPointerSetValueAlloc(
    allocator: std.mem.Allocator,
    meta_bytes: []const u8,
    ptr: []const u8,
    value_bytes: []const u8,
    mode: MetaValueMode,
) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = try std.json.parseFromSlice(std.json.Value, a, meta_bytes, .{});
    var root = parsed.value;

    if (ptr.len == 0 or ptr[0] != '/') return error.InvalidPointer;

    // Tokenize pointer
    var tokens = std.ArrayList([]u8).init(a);
    var it = std.mem.splitScalar(u8, ptr[1..], '/');
    while (it.next()) |raw| try tokens.append(try decodeJsonPointerTokenAlloc(a, raw));
    if (tokens.items.len == 0) return error.InvalidPointer;

    // Determine value (parsed in arena when JSON)
    var new_val: std.json.Value = undefined;
    switch (mode) {
        .string => new_val = .{ .string = value_bytes },
        .json => {
            const pv = try std.json.parseFromSlice(std.json.Value, a, value_bytes, .{});
            new_val = pv.value;
        },
        .auto => {
            const pv = std.json.parseFromSlice(std.json.Value, a, value_bytes, .{}) catch null;
            if (pv) |pp| new_val = pp.value else new_val = .{ .string = value_bytes };
        },
    }

    // Walk to parent
    var cur = &root;
    var idx: usize = 0;
    while (idx + 1 < tokens.items.len) : (idx += 1) {
        const key = tokens.items[idx];

        if (cur.* != .object) {
            cur.* = .{ .object = std.json.ObjectMap.init(a) };
        }

        const obj = &cur.*.object;
        if (obj.getPtr(key)) |next| {
            cur = next;
        } else {
            try obj.put(key, .{ .object = std.json.ObjectMap.init(a) });
            cur = obj.getPtr(key).?;
        }
    }

    const last = tokens.items[tokens.items.len - 1];
    if (cur.* != .object) cur.* = .{ .object = std.json.ObjectMap.init(a) };
    try cur.*.object.put(last, new_val);

    return try canonicalJsonAlloc(allocator, a, root);
}

fn jsonMergeInto(allocator: std.mem.Allocator, dst: *std.json.Value, patch: std.json.Value) !void {
    if (patch != .object) {
        dst.* = patch;
        return;
    }
    if (dst.* != .object) dst.* = .{ .object = std.json.ObjectMap.init(allocator) };

    var it = patch.object.iterator();
    while (it.next()) |kv| {
        const k = kv.key_ptr.*;
        const pv = kv.value_ptr.*;

        if (dst.*.object.getPtr(k)) |dv| {
            if (dv.* == .object and pv == .object) {
                try jsonMergeInto(allocator, dv, pv);
            } else {
                dv.* = pv;
            }
        } else {
            try dst.*.object.put(k, pv);
        }
    }
}

pub fn metaMergePatchAlloc(allocator: std.mem.Allocator, base_bytes: []const u8, patch_bytes: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const base_p = try std.json.parseFromSlice(std.json.Value, a, base_bytes, .{});
    const patch_p = try std.json.parseFromSlice(std.json.Value, a, patch_bytes, .{});

    var base = base_p.value;
    try jsonMergeInto(a, &base, patch_p.value);

    return try canonicalJsonAlloc(allocator, a, base);
}

pub const MetaValueMode = enum {
    auto,
    string,
    json,
};

fn metaValueParseToJsonAlloc(allocator: std.mem.Allocator, value_bytes: []const u8, mode: MetaValueMode) ![]u8 {
    switch (mode) {
        .string => {
            // Wrap string as JSON string literal
            var out = std.ArrayList(u8).init(allocator);
            errdefer out.deinit();
            try std.json.stringify(value_bytes, .{}, out.writer());
            return out.toOwnedSlice();
        },
        .json => {
            // Validate and return as-is
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            _ = try std.json.parseFromSlice(std.json.Value, arena.allocator(), value_bytes, .{});
            return try allocator.dupe(u8, value_bytes);
        },
        .auto => {
            // Try JSON first, fall back to string
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            if (std.json.parseFromSlice(std.json.Value, arena.allocator(), value_bytes, .{})) |_| {
                return try allocator.dupe(u8, value_bytes);
            } else |_| {
                var out = std.ArrayList(u8).init(allocator);
                errdefer out.deinit();
                try std.json.stringify(value_bytes, .{}, out.writer());
                return out.toOwnedSlice();
            }
        },
    }
}

pub const RewriteMetaSetOptions = struct {
    allocator: std.mem.Allocator,
    in_path: []const u8,
    out_path: []const u8,
    json_pointer: []const u8,
    value_bytes: []const u8,
    value_mode: MetaValueMode = .auto,
    strip_signature: bool = false,
};

pub const RewriteMetaPatchOptions = struct {
    allocator: std.mem.Allocator,
    in_path: []const u8,
    out_path: []const u8,
    patch_json_path: []const u8,
    strip_signature: bool = false,
};


// ---- ODM helpers (meta_bin) ----

fn odmPointerGetStringOrNullAlloc(allocator: std.mem.Allocator, odm_bytes: []const u8, ptr: []const u8) !?[]u8 {
    const odm = @import("odm.zig");
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const root = try odm.decodeAlloc(arena.allocator(), odm_bytes, .{ .require_canonical = true });

    if (ptr.len == 0 or ptr[0] != '/') return error.InvalidPointer;
    var it = std.mem.splitScalar(u8, ptr[1..], '/');

    var cur = root;
    while (it.next()) |raw| {
        const tok = try decodeJsonPointerTokenAlloc(arena.allocator(), raw);

        switch (cur) {
            .map => |entries| {
                var found: ?odm.Value = null;
                for (entries) |e| {
                    if (std.mem.eql(u8, e.key, tok)) {
                        found = e.value;
                        break;
                    }
                }
                if (found == null) return null;
                cur = found.?;
            },
            else => return null,
        }
    }

    if (cur != .string) return null;
    return try allocator.dupe(u8, cur.string);
}

fn jsonToOdmAlloc(allocator: std.mem.Allocator, json_bytes: []const u8) !@import("odm.zig").Value {
    const odm = @import("odm.zig");
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{});
    defer parsed.deinit();
    return try jsonValueToOdmAlloc(allocator, parsed.value);
}

fn jsonValueToOdmAlloc(allocator: std.mem.Allocator, v: std.json.Value) !@import("odm.zig").Value {
    const odm = @import("odm.zig");
    return switch (v) {
        .null => odm.Value{ .null = {} },
        .bool => |b| odm.Value{ .bool = b },
        .integer => |i| odm.Value{ .int = @intCast(i) },
        .float => return error.FloatNotSupported,
        .string => |s| odm.Value{ .string = try allocator.dupe(u8, s) },
        .array => |a| blk: {
            var items = try allocator.alloc(odm.Value, a.items.len);
            var idx: usize = 0;
            while (idx < a.items.len) : (idx += 1) {
                items[idx] = try jsonValueToOdmAlloc(allocator, a.items[idx]);
            }
            break :blk odm.Value{ .array = items };
        },
        .object => |o| blk: {
            var keys = std.ArrayList([]const u8).init(allocator);
            defer keys.deinit();
            var it = o.iterator();
            while (it.next()) |kv| try keys.append(kv.key_ptr.*);
            std.sort.block([]const u8, keys.items, {}, struct {
                fn less(_: void, a: []const u8, b: []const u8) bool { return std.mem.lessThan(u8, a, b); }
            }.less);

            var entries = try allocator.alloc(odm.MapEntry, keys.items.len);
            for (keys.items, 0..) |k, i| {
                const vv = o.get(k).?;
                entries[i] = .{
                    .key = try allocator.dupe(u8, k),
                    .value = try jsonValueToOdmAlloc(allocator, vv),
                };
            }
            break :blk odm.Value{ .map = entries };
        },
    };
}

fn odmToJsonAlloc(allocator: std.mem.Allocator, v: @import("odm.zig").Value) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try writeOdmAsJson(&out, v);
    return out.toOwnedSlice();
}

fn writeOdmAsJson(out: *std.ArrayList(u8), v: @import("odm.zig").Value) !void {
    const odm = @import("odm.zig");
    _ = odm;
    switch (v) {
        .null => try out.appendSlice("null"),
        .bool => |b| try out.appendSlice(if (b) "true" else "false"),
        .int => |i| try out.writer().print("{d}", .{i}),
        .uint => |u| try out.writer().print("{d}", .{u}),
        .bytes => |b| blk: {
            const hex = try bytesToHexAlloc(out.allocator, b);
            defer out.allocator.free(hex);
            try out.writer().print("{s}", .{std.json.fmtString(hex)});
            break :blk;
        },
        .string => |s| try out.writer().print("{s}", .{std.json.fmtString(s)}),
        .array => |arr| {
            try out.append('[');
            for (arr, 0..) |it, i| {
                if (i != 0) try out.append(',');
                try writeOdmAsJson(out, it);
            }
            try out.append(']');
        },
        .map => |entries| {
            try out.append('{');
            for (entries, 0..) |e, i| {
                if (i != 0) try out.append(',');
                try out.writer().print("{s}:", .{std.json.fmtString(e.key)});
                try writeOdmAsJson(out, e.value);
            }
            try out.append('}');
        },
    }
}

fn dupOdmValueAlloc(allocator: std.mem.Allocator, v: @import("odm.zig").Value) !@import("odm.zig").Value {
    const odm = @import("odm.zig");
    return switch (v) {
        .null => odm.Value{ .null = {} },
        .bool => |b| odm.Value{ .bool = b },
        .int => |i| odm.Value{ .int = i },
        .uint => |u| odm.Value{ .uint = u },
        .bytes => |b| odm.Value{ .bytes = try allocator.dupe(u8, b) },
        .string => |s| odm.Value{ .string = try allocator.dupe(u8, s) },
        .array => |arr| blk: {
            var out = try allocator.alloc(odm.Value, arr.len);
            for (arr, 0..) |it, i| out[i] = try dupOdmValueAlloc(allocator, it);
            break :blk odm.Value{ .array = out };
        },
        .map => |entries| blk: {
            var out = try allocator.alloc(odm.MapEntry, entries.len);
            for (entries, 0..) |e, i| {
                out[i] = .{ .key = try allocator.dupe(u8, e.key), .value = try dupOdmValueAlloc(allocator, e.value) };
            }
            break :blk odm.Value{ .map = out };
        },
    };
}

fn freeOdmValue(allocator: std.mem.Allocator, v: @import("odm.zig").Value) void {
    const odm = @import("odm.zig");
    _ = odm;
    switch (v) {
        .bytes => |b| allocator.free(b),
        .string => |s| allocator.free(s),
        .array => |arr| {
            for (arr) |it| freeOdmValue(allocator, it);
            allocator.free(arr);
        },
        .map => |entries| {
            for (entries) |e| {
                allocator.free(e.key);
                freeOdmValue(allocator, e.value);
            }
            allocator.free(entries);
        },
        else => {},
    }
}

fn odmSetPointerAlloc(allocator: std.mem.Allocator, root: @import("odm.zig").Value, ptr: []const u8, new_value: @import("odm.zig").Value) !@import("odm.zig").Value {
    const odm = @import("odm.zig");
    if (ptr.len == 0 or ptr[0] != '/') return error.InvalidPointer;

    var toks = std.ArrayList([]const u8).init(allocator);
    defer toks.deinit();
    var it = std.mem.splitScalar(u8, ptr[1..], '/');
    while (it.next()) |raw| {
        const tok = try decodeJsonPointerTokenAlloc(allocator, raw);
        try toks.append(tok);
    }
    defer for (toks.items) |t| allocator.free(t);

    return try odmSetRec(allocator, root, toks.items, 0, new_value);
}

fn odmSetRec(allocator: std.mem.Allocator, cur: @import("odm.zig").Value, toks: []const []const u8, idx: usize, new_value: @import("odm.zig").Value) !@import("odm.zig").Value {
    const odm = @import("odm.zig");
    if (idx >= toks.len) return new_value;

    const key = toks[idx];

    const existing_entries: []odm.MapEntry = switch (cur) {
        .map => |e| e,
        else => &.{},
    };

    var list = std.ArrayList(odm.MapEntry).init(allocator);
    errdefer {
        for (list.items) |e| {
            allocator.free(e.key);
            freeOdmValue(allocator, e.value);
        }
        list.deinit();
    }

    var found = false;
    for (existing_entries) |e| {
        if (std.mem.eql(u8, e.key, key)) {
            found = true;
            const replaced = try odmSetRec(allocator, e.value, toks, idx + 1, new_value);
            try list.append(.{ .key = try allocator.dupe(u8, e.key), .value = replaced });
        } else {
            try list.append(.{ .key = try allocator.dupe(u8, e.key), .value = try dupOdmValueAlloc(allocator, e.value) });
        }
    }

    if (!found) {
        // Create nested maps down to leaf.
        var v = new_value;
        var j: isize = @intCast(toks.len - 1);
        while (j > @as(isize, @intCast(idx))) : (j -= 1) {
            const k = toks[@intCast(j)];
            var one = try allocator.alloc(odm.MapEntry, 1);
            one[0] = .{ .key = try allocator.dupe(u8, k), .value = v };
            v = odm.Value{ .map = one };
        }
        try list.append(.{ .key = try allocator.dupe(u8, key), .value = v });
    }

    std.sort.block(odm.MapEntry, list.items, {}, struct {
        fn less(_: void, a: odm.MapEntry, b: odm.MapEntry) bool { return std.mem.lessThan(u8, a.key, b.key); }
    }.less);

    var kprev: ?[]const u8 = null;
    for (list.items) |e| {
        if (kprev) |pk| if (std.mem.eql(u8, pk, e.key)) return error.DuplicateKey;
        kprev = e.key;
    }

    const out_entries = try allocator.alloc(odm.MapEntry, list.items.len);
    std.mem.copyForwards(odm.MapEntry, out_entries, list.items);
    list.deinit();

    return odm.Value{ .map = out_entries };
}

pub const RewriteMetaBinSetOptions = struct {
    allocator: std.mem.Allocator,
    in_path: []const u8,
    out_path: []const u8,
    pointer: []const u8,
    value_text: []const u8,
    value_mode: MetaValueMode = .auto,
    strip_signature: bool = false,
};

pub const RewriteMetaBinPatchOptions = struct {
    allocator: std.mem.Allocator,
    in_path: []const u8,
    out_path: []const u8,
    patch_json_path: []const u8,
    strip_signature: bool = false,
};

pub fn rewriteMetaBinSet(opts: RewriteMetaBinSetOptions) !void {
    const odm = @import("odm.zig");
    var in_file = try std.fs.cwd().openFile(opts.in_path, .{ .mode = .read_only });
    defer in_file.close();

    const st = try in_file.stat();
    const file_len: u64 = @intCast(st.size);

    var of = try OdiFile.readFromFile(opts.allocator, in_file);
    defer of.deinit(opts.allocator);

    try of.validateStructure(file_len);

    const ms = of.findSection(.meta_bin) orelse return error.MissingMeta;
    const old_bytes = try readSectionAlloc(opts.allocator, in_file, ms.offset, ms.length, 32 * 1024 * 1024);
    defer opts.allocator.free(old_bytes);

    var arena = std.heap.ArenaAllocator.init(opts.allocator);
    defer arena.deinit();
    const root = try odm.decodeAlloc(arena.allocator(), old_bytes, .{ .require_canonical = true });

    const new_val_json = try metaValueParseToJsonAlloc(opts.allocator, opts.value_text, opts.value_mode);
    defer opts.allocator.free(new_val_json);

    const odm_val = try jsonToOdmAlloc(opts.allocator, new_val_json);
    defer freeOdmValue(opts.allocator, odm_val);

    const updated = try odmSetPointerAlloc(opts.allocator, root, opts.pointer, odm_val);
    defer freeOdmValue(opts.allocator, updated);

    const new_odm_bytes = try odm.encodeAlloc(opts.allocator, updated);
    defer opts.allocator.free(new_odm_bytes);

    try odm.validateCanonical(new_odm_bytes);

    try rewriteOdiWithSectionReplacement(.{
        .allocator = opts.allocator,
        .in_file = in_file,
        .in_of = &of,
        .out_path = opts.out_path,
        .target = .meta_bin,
        .new_bytes = new_odm_bytes,
        .strip_signature = opts.strip_signature,
    });
}

pub fn rewriteMetaBinPatch(opts: RewriteMetaBinPatchOptions) !void {
    const odm = @import("odm.zig");
    var in_file = try std.fs.cwd().openFile(opts.in_path, .{ .mode = .read_only });
    defer in_file.close();

    const st = try in_file.stat();
    const file_len: u64 = @intCast(st.size);

    var of = try OdiFile.readFromFile(opts.allocator, in_file);
    defer of.deinit(opts.allocator);

    try of.validateStructure(file_len);

    const ms = of.findSection(.meta_bin) orelse return error.MissingMeta;
    const old_bytes = try readSectionAlloc(opts.allocator, in_file, ms.offset, ms.length, 32 * 1024 * 1024);
    defer opts.allocator.free(old_bytes);

    var arena = std.heap.ArenaAllocator.init(opts.allocator);
    defer arena.deinit();
    const root = try odm.decodeAlloc(arena.allocator(), old_bytes, .{ .require_canonical = true });

    const old_json = try odmToJsonAlloc(opts.allocator, root);
    defer opts.allocator.free(old_json);

    const patch_bytes = try readFileAlloc(opts.allocator, opts.patch_json_path, 16 * 1024 * 1024);
    defer opts.allocator.free(patch_bytes);

    const merged_json = try metaMergePatchAlloc(opts.allocator, old_json, patch_bytes);
    defer opts.allocator.free(merged_json);

    const new_root = try jsonToOdmAlloc(opts.allocator, merged_json);
    defer freeOdmValue(opts.allocator, new_root);

    const new_odm_bytes = try odm.encodeAlloc(opts.allocator, new_root);
    defer opts.allocator.free(new_odm_bytes);

    try odm.validateCanonical(new_odm_bytes);

    try rewriteOdiWithSectionReplacement(.{
        .allocator = opts.allocator,
        .in_file = in_file,
        .in_of = &of,
        .out_path = opts.out_path,
        .target = .meta_bin,
        .new_bytes = new_odm_bytes,
        .strip_signature = opts.strip_signature,
    });
}

const RewriteReplaceOptions = struct {
    allocator: std.mem.Allocator,
    in_file: std.fs.File,
    in_of: *const OdiFile,
    out_path: []const u8,
    target: SectionType,
    new_bytes: []const u8,
    strip_signature: bool,
};

fn rewriteOdiWithSectionReplacement(opts: RewriteReplaceOptions) !void {
    var out_file = try std.fs.cwd().createFile(opts.out_path, .{ .truncate = true, .read = true });
    defer out_file.close();

    const payload = opts.in_of.findSection(.payload) orelse return error.MissingPayload;
    const manifest = opts.in_of.findSection(.manifest) orelse return error.MissingManifest;

    const sig_opt = opts.in_of.findSection(.sig);
    const keep_sig = (sig_opt != null) and !opts.strip_signature;

    _ = opts.in_of.findSection(opts.target) orelse return error.MissingMeta;

    const header_size = @sizeOf(Header);
    const table_entry_size = @sizeOf(Section);

    var section_count: usize = 0;
    section_count += 1;
    section_count += 1;
    section_count += 1;
    if (keep_sig) section_count += 1;

    const reserve: u64 = @intCast(header_size + table_entry_size * section_count);

    var cur_off: u64 = reserve;

    const payload_off = cur_off;
    cur_off += payload.length;

    const target_off = cur_off;
    cur_off += @intCast(opts.new_bytes.len);

    const manifest_off = cur_off;
    cur_off += manifest.length;

    var sig_off: u64 = 0;
    var sig_len: u64 = 0;
    if (keep_sig) {
        sig_off = cur_off;
        sig_len = sig_opt.?.length;
        cur_off += sig_len;
    }

    var hdr = Header{
        .magic = .{ 'O', 'D', 'I', '1' },
        .version = 1,
        .section_count = @intCast(section_count),
        .table_offset = @intCast(@sizeOf(Header)),
        .table_length = @intCast(table_entry_size * section_count),
        .reserved = .{0} ** 32,
    };

    const sections = try opts.allocator.alloc(Section, section_count);
    defer opts.allocator.free(sections);

    const payload_bytes = try readSectionAlloc(opts.allocator, opts.in_file, payload.offset, payload.length, 256 * 1024 * 1024);
    defer opts.allocator.free(payload_bytes);
    const manifest_bytes = try readSectionAlloc(opts.allocator, opts.in_file, manifest.offset, manifest.length, 256 * 1024 * 1024);
    defer opts.allocator.free(manifest_bytes);

    var sig_bytes: ?[]u8 = null;
    if (keep_sig) sig_bytes = try readSectionAlloc(opts.allocator, opts.in_file, sig_opt.?.offset, sig_opt.?.length, 64 * 1024 * 1024);
    defer if (sig_bytes) |b| opts.allocator.free(b);

    var si: usize = 0;
    sections[si] = .{
        .stype = @intFromEnum(SectionType.payload),
        .reserved0 = 0,
        .offset = payload_off,
        .length = payload.length,
        .hash_alg = 1,
        .hash_len = 32,
        .reserved1 = 0,
        .hash = sha256Bytes(payload_bytes),
        .reserved2 = 0,
    };
    si += 1;

    sections[si] = .{
        .stype = @intFromEnum(opts.target),
        .reserved0 = 0,
        .offset = target_off,
        .length = @intCast(opts.new_bytes.len),
        .hash_alg = 1,
        .hash_len = 32,
        .reserved1 = 0,
        .hash = sha256Bytes(opts.new_bytes),
        .reserved2 = 0,
    };
    si += 1;

    sections[si] = .{
        .stype = @intFromEnum(SectionType.manifest),
        .reserved0 = 0,
        .offset = manifest_off,
        .length = manifest.length,
        .hash_alg = 1,
        .hash_len = 32,
        .reserved1 = 0,
        .hash = sha256Bytes(manifest_bytes),
        .reserved2 = 0,
    };
    si += 1;

    if (keep_sig) {
        sections[si] = .{
            .stype = @intFromEnum(SectionType.sig),
            .reserved0 = 0,
            .offset = sig_off,
            .length = sig_len,
            .hash_alg = 1,
            .hash_len = 32,
            .reserved1 = 0,
            .hash = sha256Bytes(sig_bytes.?),
            .reserved2 = 0,
        };
        si += 1;
    }

    try out_file.writer().writeStruct(hdr);
    for (sections) |s| try out_file.writer().writeStruct(s);

    try out_file.writer().writeAll(payload_bytes);
    try out_file.writer().writeAll(opts.new_bytes);
    try out_file.writer().writeAll(manifest_bytes);
    if (keep_sig) try out_file.writer().writeAll(sig_bytes.?);
}

pub fn rewriteMetaSet(opts: RewriteMetaSetOptions) !void {
    var in_file = try std.fs.cwd().openFile(opts.in_path, .{ .mode = .read_only });
    defer in_file.close();

    const st = try in_file.stat();
    const file_len: u64 = @intCast(st.size);

    var of = try OdiFile.readFromFile(opts.allocator, in_file);
    defer of.deinit(opts.allocator);

    try of.validateStructure(file_len);

    const ms = of.findSection(.meta) orelse return error.MissingMeta;
    const old_meta = try readSectionAlloc(opts.allocator, in_file, ms.offset, ms.length, 32 * 1024 * 1024);
    defer opts.allocator.free(old_meta);

    const new_meta = try metaPointerSetValueAlloc(
        opts.allocator,
        old_meta,
        opts.json_pointer,
        opts.value_bytes,
        opts.value_mode,
    );
    defer opts.allocator.free(new_meta);

    try rewriteOdiWithNewMeta(.{
        .allocator = opts.allocator,
        .in_file = in_file,
        .in_of = &of,
        .out_path = opts.out_path,
        .new_meta_bytes = new_meta,
        .strip_signature = opts.strip_signature,
    });
}

pub fn rewriteMetaPatch(opts: RewriteMetaPatchOptions) !void {
    var in_file = try std.fs.cwd().openFile(opts.in_path, .{ .mode = .read_only });
    defer in_file.close();

    const st = try in_file.stat();
    const file_len: u64 = @intCast(st.size);

    var of = try OdiFile.readFromFile(opts.allocator, in_file);
    defer of.deinit(opts.allocator);

    try of.validateStructure(file_len);

    const ms = of.findSection(.meta) orelse return error.MissingMeta;
    const old_meta = try readSectionAlloc(opts.allocator, in_file, ms.offset, ms.length, 32 * 1024 * 1024);
    defer opts.allocator.free(old_meta);

    const patch_bytes = try readFileAlloc(opts.allocator, opts.patch_json_path, 16 * 1024 * 1024);
    defer opts.allocator.free(patch_bytes);

    const new_meta = try metaMergePatchAlloc(opts.allocator, old_meta, patch_bytes);
    defer opts.allocator.free(new_meta);

    try rewriteOdiWithNewMeta(.{
        .allocator = opts.allocator,
        .in_file = in_file,
        .in_of = &of,
        .out_path = opts.out_path,
        .new_meta_bytes = new_meta,
        .strip_signature = opts.strip_signature,
    });
}

const RewriteMetaOptions = struct {
    allocator: std.mem.Allocator,
    in_file: std.fs.File,
    in_of: *const OdiFile,
    out_path: []const u8,
    new_meta_bytes: []const u8,
    strip_signature: bool,
};

fn rewriteOdiWithNewMeta(opts: RewriteMetaOptions) !void {
    var out_file = try std.fs.cwd().createFile(opts.out_path, .{ .truncate = true, .read = true });
    defer out_file.close();

    const payload = opts.in_of.findSection(.payload) orelse return error.MissingPayload;
    const manifest = opts.in_of.findSection(.manifest) orelse return error.MissingManifest;

    const sig_opt = opts.in_of.findSection(.sig);
    const keep_sig = (sig_opt != null) and !opts.strip_signature;

    const header_size = @sizeOf(Header);
    const table_entry_size = @sizeOf(Section);

    var section_count: usize = 0;
    section_count += 1; // payload
    section_count += 1; // meta (new)
    section_count += 1; // manifest
    if (keep_sig) section_count += 1;

    const reserve: u64 = @intCast(header_size + table_entry_size * section_count);
    try out_file.seekTo(reserve);
    var cursor: u64 = reserve;

    var sections = std.ArrayList(Section).init(opts.allocator);
    defer sections.deinit();

    const payload_s = try copySectionAndHash(opts.in_file, out_file, payload.offset, payload.length, .sha256, .payload, &cursor);
    try sections.append(payload_s);

    const meta_s = try writeBytesAndHash(out_file, .meta, opts.new_meta_bytes, .sha256, &cursor);
    try sections.append(meta_s);

    const manifest_s = try copySectionAndHash(opts.in_file, out_file, manifest.offset, manifest.length, .sha256, .manifest, &cursor);
    try sections.append(manifest_s);

    if (keep_sig) {
        const sig = sig_opt.?;
        const sig_s = try copySectionAndHash(opts.in_file, out_file, sig.offset, sig.length, .sha256, .sig, &cursor);
        try sections.append(sig_s);
    }

    try out_file.seekTo(0);
    var hdr = Header.initDefault();
    hdr.section_count = @intCast(sections.items.len);
    hdr.table_offset = header_size;
    hdr.table_length = @intCast(sections.items.len * @sizeOf(Section));

    try out_file.writeAll(std.mem.asBytes(&hdr));
    for (sections.items) |s| try out_file.writeAll(std.mem.asBytes(&s));
}

// ---- Provenance (minimal) ----

pub const Provenance = struct {
    has_meta: bool,
    odi_id: ?[]u8 = null,
    version: ?[]u8 = null,
    build: ?[]u8 = null,
    source: ?[]u8 = null,

    pub fn deinit(self: *Provenance, allocator: std.mem.Allocator) void {
        if (self.odi_id) |s| allocator.free(s);
        if (self.version) |s| allocator.free(s);
        if (self.build) |s| allocator.free(s);
        if (self.source) |s| allocator.free(s);
    }

    pub fn toTextAlloc(self: *const Provenance, allocator: std.mem.Allocator) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();

        try out.appendSlice("ODI provenance\n");
        try out.writer().print("  metaPresent: {s}\n", .{if (self.has_meta) "true" else "false"});
        try out.writer().print("  odi.id: {s}\n", .{if (self.odi_id) |s| s else "(missing)"});
        try out.writer().print("  odi.version: {s}\n", .{if (self.version) |s| s else "(missing)"});
        try out.writer().print("  build: {s}\n", .{if (self.build) |s| s else "(missing)"});
        try out.writer().print("  source: {s}\n", .{if (self.source) |s| s else "(missing)"});
        return out.toOwnedSlice();
    }

    pub fn toJsonAlloc(self: *const Provenance, allocator: std.mem.Allocator) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var root = std.json.ObjectMap.init(a);
        try root.put("type", .{ .string = "provenance" });
        try root.put("metaPresent", .{ .bool = self.has_meta });

        if (self.odi_id) |s| try root.put("odi.id", .{ .string = s });
        if (self.version) |s| try root.put("odi.version", .{ .string = s });
        if (self.build) |s| try root.put("build", .{ .string = s });
        if (self.source) |s| try root.put("source", .{ .string = s });

        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try std.json.stringify(.{ .object = root }, .{ .whitespace = .minified }, buf.writer());
        return buf.toOwnedSlice();
    }
};

pub fn provenanceFromFileAlloc(allocator: std.mem.Allocator, odi_path: []const u8, verify_hashes: bool) !Provenance {
    var file = try std.fs.cwd().openFile(odi_path, .{ .mode = .read_only });
    defer file.close();

    const st = try file.stat();
    const file_len: u64 = @intCast(st.size);

    var of = try OdiFile.readFromFile(allocator, file);
    defer of.deinit(allocator);
    try of.validateStructure(file_len);

    if (verify_hashes) try of.verifySectionHashes(file);

    const ms_bin = of.findSection(.meta_bin);
    const ms_json = of.findSection(.meta);
    if (ms_bin == null and ms_json == null) return .{ .has_meta = false };

    const ms = if (ms_bin != null) ms_bin.? else ms_json.?;
    const meta_bytes = try readSectionAlloc(allocator, file, ms.offset, ms.length, 32 * 1024 * 1024);
    defer allocator.free(meta_bytes);

    var prov: Provenance = .{ .has_meta = true };
    errdefer prov.deinit(allocator);

    // Try common pointers
    prov.odi_id = metaPointerGetStringOrNullAlloc(allocator, meta_bytes, "/odi/id") catch null;
    prov.version = metaPointerGetStringOrNullAlloc(allocator, meta_bytes, "/odi/version") catch null;
    prov.build = metaPointerGetStringOrNullAlloc(allocator, meta_bytes, "/build") catch null;
    prov.source = metaPointerGetStringOrNullAlloc(allocator, meta_bytes, "/source") catch null;

    return prov;
}

fn metaPointerGetStringOrNullAlloc(allocator: std.mem.Allocator, meta_bytes: []const u8, ptr: []const u8) ![]u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, meta_bytes, .{});
    defer parsed.deinit();

    var v = parsed.value;
    if (ptr.len == 0 or ptr[0] != '/') return error.InvalidPointer;

    var it = std.mem.splitScalar(u8, ptr[1..], '/');
    while (it.next()) |raw| {
        const tok = try decodeJsonPointerTokenAlloc(allocator, raw);
        defer allocator.free(tok);

        if (v != .object) return error.PointerNotFound;
        v = v.object.get(tok) orelse return error.PointerNotFound;
    }

    if (v != .string) return error.NotAString;
    return try allocator.dupe(u8, v.string);
}

// ---- check-tree ----

pub const TreeCheckReport = struct {
    ok: bool,
    missing: [][]const u8,
    extra: [][]const u8,
    changed: []DiffChanged,

    pub fn deinit(self: *const TreeCheckReport, allocator: std.mem.Allocator) void {
        for (self.missing) |p| allocator.free(p);
        allocator.free(self.missing);
        for (self.extra) |p| allocator.free(p);
        allocator.free(self.extra);
        for (self.changed) |c| {
            allocator.free(c.path);
            allocator.free(c.reason);
            if (c.from) |f| allocator.free(f);
            if (c.to) |t| allocator.free(t);
        }
        allocator.free(self.changed);
    }

    pub fn toTextAlloc(self: *const TreeCheckReport, allocator: std.mem.Allocator) ![]u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();

        try out.appendSlice("TREE check\n");
        try out.writer().print("  ok: {s}\n", .{if (self.ok) "true" else "false"});
        try out.writer().print("  missing: {d}\n  extra: {d}\n  changed: {d}\n\n", .{ self.missing.len, self.extra.len, self.changed.len });

        for (self.missing) |p| try out.writer().print("- {s}\n", .{p});
        for (self.extra) |p| try out.writer().print("+ {s}\n", .{p});
        for (self.changed) |ch| {
            if (ch.from != null and ch.to != null) {
                try out.writer().print("~ {s} {s} {s} -> {s}\n", .{ ch.path, ch.reason, ch.from.?, ch.to.? });
            } else {
                try out.writer().print("~ {s} {s}\n", .{ ch.path, ch.reason });
            }
        }
        return out.toOwnedSlice();
    }

    pub fn toJsonAlloc(self: *const TreeCheckReport, allocator: std.mem.Allocator) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var root = std.json.ObjectMap.init(a);
        try root.put("type", .{ .string = "treeCheck" });
        try root.put("ok", .{ .bool = self.ok });

        var missing_arr = std.json.Array.init(a);
        for (self.missing) |p| try missing_arr.append(.{ .string = p });
        try root.put("missing", .{ .array = missing_arr });

        var extra_arr = std.json.Array.init(a);
        for (self.extra) |p| try extra_arr.append(.{ .string = p });
        try root.put("extra", .{ .array = extra_arr });

        var changed_arr = std.json.Array.init(a);
        for (self.changed) |ch| {
            var o = std.json.ObjectMap.init(a);
            try o.put("path", .{ .string = ch.path });
            try o.put("reason", .{ .string = ch.reason });
            if (ch.from) |f| try o.put("from", .{ .string = f });
            if (ch.to) |t| try o.put("to", .{ .string = t });
            try changed_arr.append(.{ .object = o });
        }
        try root.put("changed", .{ .array = changed_arr });

        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try std.json.stringify(.{ .object = root }, .{ .whitespace = .minified }, buf.writer());
        return buf.toOwnedSlice();
    }
};

pub fn checkTreeAgainstManifestAlloc(opts: struct {
    allocator: std.mem.Allocator,
    root_dir: []const u8,
    odi_path: []const u8,
    mode: DiffMode,
    policy: DiffPolicy,
}) !TreeCheckReport {
    const manifest_bytes = try readManifestAlloc(opts.allocator, opts.odi_path);
    defer opts.allocator.free(manifest_bytes);

    var man = try parseManifestToMap(opts.allocator, manifest_bytes);
    defer freeManifestMap(opts.allocator, &man);

    var seen = std.StringHashMap(void).init(opts.allocator);
    defer {
        var it = seen.iterator();
        while (it.next()) |kv| opts.allocator.free(kv.key_ptr.*);
        seen.deinit();
    }

    var extra = std.ArrayList([]const u8).init(opts.allocator);
    errdefer {
        for (extra.items) |p| opts.allocator.free(p);
        extra.deinit();
    }
    var changed = std.ArrayList(DiffChanged).init(opts.allocator);
    errdefer {
        for (changed.items) |c| {
            opts.allocator.free(c.path);
            opts.allocator.free(c.reason);
            if (c.from) |f| opts.allocator.free(f);
            if (c.to) |t| opts.allocator.free(t);
        }
        changed.deinit();
    }

    // Walk filesystem
    var dir = try std.fs.cwd().openDir(opts.root_dir, .{ .iterate = true });
    defer dir.close();

    try walkDirCompare(opts.allocator, &dir, "", &man, &seen, &extra, &changed, opts.mode, opts.policy);

    var missing = std.ArrayList([]const u8).init(opts.allocator);
    errdefer {
        for (missing.items) |p| opts.allocator.free(p);
        missing.deinit();
    }

    // Missing: manifest entries not seen
    var it = man.iterator();
    while (it.next()) |kv| {
        const p = kv.key_ptr.*;
        if (!seen.contains(p)) {
            if (!reachedLimit(opts.policy, missing.items.len, extra.items.len, changed.items.len)) {
                try missing.append(try opts.allocator.dupe(u8, p));
            }
        }
    }

    std.sort.block([]const u8, missing.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool { return std.mem.lessThan(u8, a, b); }
    }.less);
    std.sort.block([]const u8, extra.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool { return std.mem.lessThan(u8, a, b); }
    }.less);
    std.sort.block(DiffChanged, changed.items, {}, struct {
        fn less(_: void, a: DiffChanged, b: DiffChanged) bool { return std.mem.lessThan(u8, a.path, b.path); }
    }.less);

    const ok = (missing.items.len == 0 and extra.items.len == 0 and changed.items.len == 0);
    return .{
        .ok = ok,
        .missing = try missing.toOwnedSlice(),
        .extra = try extra.toOwnedSlice(),
        .changed = try changed.toOwnedSlice(),
    };
}

fn walkDirCompare(
    allocator: std.mem.Allocator,
    dir: *std.fs.Dir,
    rel_prefix: []const u8,
    man: *std.StringHashMap(ManifestEntry),
    seen: *std.StringHashMap(void),
    extra: *std.ArrayList([]const u8),
    changed: *std.ArrayList(DiffChanged),
    mode: DiffMode,
    policy: DiffPolicy,
) !void {
    var it = dir.iterate();
    while (try it.next()) |e| {
        if (policy.fail_fast and (extra.items.len + changed.items.len) > 0) return;

        const rel = if (rel_prefix.len == 0)
            try allocator.dupe(u8, e.name)
        else
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ rel_prefix, e.name });
        defer allocator.free(rel);

        const key = try allocator.dupe(u8, rel);
        defer allocator.free(key);

        // Track everything in tree
        if (!seen.contains(key)) try seen.put(try allocator.dupe(u8, key), {});

        const ment_opt = man.get(key);

        // Determine actual kind string
        const actual_kind: []const u8 = switch (e.kind) {
            .directory => "dir",
            .file => "file",
            .sym_link => "symlink",
            else => continue,
        };

        if (ment_opt == null) {
            if (!reachedLimit(policy, 0, extra.items.len, changed.items.len)) {
                try extra.append(try allocator.dupe(u8, key));
            }
        } else {
            const ment = ment_opt.?;

            // Kind must match
            if (!std.mem.eql(u8, ment.kind, actual_kind)) {
                if (!reachedLimit(policy, 0, extra.items.len, changed.items.len)) {
                    try changed.append(.{
                        .path = try allocator.dupe(u8, key),
                        .reason = try allocator.dupe(u8, "kind"),
                        .from = try allocator.dupe(u8, ment.kind),
                        .to = try allocator.dupe(u8, actual_kind),
                    });
                }
            }

            // Stat for files/dirs. For symlinks, lstat is not available via portable std, so we only check target.
            if (e.kind == .file or e.kind == .directory) {
                const st = try dir.statFile(e.name);

                if (ment.size) |want| {
                    const got: u64 = @intCast(st.size);
                    if (got != want) {
                        if (!reachedLimit(policy, 0, extra.items.len, changed.items.len)) {
                            const from = try std.fmt.allocPrint(allocator, "{d}", .{want});
                            defer allocator.free(from);
                            const to = try std.fmt.allocPrint(allocator, "{d}", .{got});
                            defer allocator.free(to);
                            try changed.append(.{
                                .path = try allocator.dupe(u8, key),
                                .reason = try allocator.dupe(u8, "size"),
                                .from = try allocator.dupe(u8, from),
                                .to = try allocator.dupe(u8, to),
                            });
                        }
                    }
                }

                if (ment.mode) |want_mode| {
                    // platform dependent, but Zig returns mode bits on POSIX
                    const got_mode: u32 = @intCast(st.mode);
                    if (got_mode != want_mode) {
                        if (!reachedLimit(policy, 0, extra.items.len, changed.items.len)) {
                            const from = try std.fmt.allocPrint(allocator, "{d}", .{want_mode});
                            defer allocator.free(from);
                            const to = try std.fmt.allocPrint(allocator, "{d}", .{got_mode});
                            defer allocator.free(to);
                            try changed.append(.{
                                .path = try allocator.dupe(u8, key),
                                .reason = try allocator.dupe(u8, "mode"),
                                .from = try allocator.dupe(u8, from),
                                .to = try allocator.dupe(u8, to),
                            });
                        }
                    }
                }

                if (ment.uid) |want_uid| {
                    const got_uid: u32 = @intCast(st.uid);
                    if (got_uid != want_uid) {
                        if (!reachedLimit(policy, 0, extra.items.len, changed.items.len)) {
                            const from = try std.fmt.allocPrint(allocator, "{d}", .{want_uid});
                            defer allocator.free(from);
                            const to = try std.fmt.allocPrint(allocator, "{d}", .{got_uid});
                            defer allocator.free(to);
                            try changed.append(.{
                                .path = try allocator.dupe(u8, key),
                                .reason = try allocator.dupe(u8, "uid"),
                                .from = try allocator.dupe(u8, from),
                                .to = try allocator.dupe(u8, to),
                            });
                        }
                    }
                }

                if (ment.gid) |want_gid| {
                    const got_gid: u32 = @intCast(st.gid);
                    if (got_gid != want_gid) {
                        if (!reachedLimit(policy, 0, extra.items.len, changed.items.len)) {
                            const from = try std.fmt.allocPrint(allocator, "{d}", .{want_gid});
                            defer allocator.free(from);
                            const to = try std.fmt.allocPrint(allocator, "{d}", .{got_gid});
                            defer allocator.free(to);
                            try changed.append(.{
                                .path = try allocator.dupe(u8, key),
                                .reason = try allocator.dupe(u8, "gid"),
                                .from = try allocator.dupe(u8, from),
                                .to = try allocator.dupe(u8, to),
                            });
                        }
                    }
                }

                if (ment.mtime) |want_mtime| {
                    // st.mtime is i64 seconds on POSIX
                    const got_mtime: i64 = @intCast(st.mtime);
                    if (got_mtime != want_mtime) {
                        if (!reachedLimit(policy, 0, extra.items.len, changed.items.len)) {
                            const from = try std.fmt.allocPrint(allocator, "{d}", .{want_mtime});
                            defer allocator.free(from);
                            const to = try std.fmt.allocPrint(allocator, "{d}", .{got_mtime});
                            defer allocator.free(to);
                            try changed.append(.{
                                .path = try allocator.dupe(u8, key),
                                .reason = try allocator.dupe(u8, "mtime"),
                                .from = try allocator.dupe(u8, from),
                                .to = try allocator.dupe(u8, to),
                            });
                        }
                    }
                }

                if (e.kind == .file and ment.sha256 != null and mode == .content) {
                    const want = ment.sha256.?;
                    const got_hex = try sha256FileHexAlloc(allocator, dir, e.name);
                    defer allocator.free(got_hex);

                    if (!std.mem.eql(u8, want, got_hex)) {
                        if (!reachedLimit(policy, 0, extra.items.len, changed.items.len)) {
                            try changed.append(.{
                                .path = try allocator.dupe(u8, key),
                                .reason = try allocator.dupe(u8, "sha256"),
                                .from = try allocator.dupe(u8, want),
                                .to = try allocator.dupe(u8, got_hex),
                            });
                        }
                    }
                }
            } else if (e.kind == .sym_link) {
                if (ment.target) |want_t| {
                    var buf: [4096]u8 = undefined;
                    const n = try dir.readLink(e.name, &buf);
                    const got_t = buf[0..n];
                    if (!std.mem.eql(u8, want_t, got_t)) {
                        if (!reachedLimit(policy, 0, extra.items.len, changed.items.len)) {
                            try changed.append(.{
                                .path = try allocator.dupe(u8, key),
                                .reason = try allocator.dupe(u8, "target"),
                                .from = try allocator.dupe(u8, want_t),
                                .to = try allocator.dupe(u8, got_t),
                            });
                        }
                    }
                }
            }
        }

        if (e.kind == .directory) {
            var child = try dir.openDir(e.name, .{ .iterate = true });
            defer child.close();
            try walkDirCompare(allocator, &child, rel, man, seen, extra, changed, mode, policy);
        }
    }
}

fn sha256FileHexAlloc(allocator: std.mem.Allocator, dir: *std.fs.Dir, name: []const u8) ![]u8 {
    var f = try dir.openFile(name, .{ .mode = .read_only });
    defer f.close();

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [1024 * 1024]u8 = undefined;
    while (true) {
        const n = try f.read(&buf);
        if (n == 0) break;
        hasher.update(buf[0..n]);
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return try bytesToHexAlloc(allocator, digest[0..]);
}