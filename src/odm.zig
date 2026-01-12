const std = @import("std");

pub const Tag = enum(u8) {
    null = 0x00,
    bool = 0x01,
    int = 0x02,
    uint = 0x03,
    bytes = 0x04,
    string = 0x05,
    array = 0x06,
    map = 0x07,
};

pub const Value = union(Tag) {
    null: void,
    bool: bool,
    int: i64,
    uint: u64,
    bytes: []const u8,
    string: []const u8,
    array: []Value,
    map: []MapEntry,
};

pub const MapEntry = struct {
    key: []const u8, // UTF-8 bytes
    value: Value,
};

pub const DecodeOptions = struct {
    // Require that input is canonical and fail otherwise.
    require_canonical: bool = true,
};

pub fn decodeAlloc(allocator: std.mem.Allocator, bytes: []const u8, opts: DecodeOptions) !Value {
    if (bytes.len < 4 or !std.mem.eql(u8, bytes[0..4], "ODM1")) return error.BadOdmMagic;
    var fbs = std.io.fixedBufferStream(bytes[4..]);
    const r = fbs.reader();
    const v = try decodeValueAlloc(allocator, r, opts);
    // Ensure no trailing bytes
    if (opts.require_canonical) {
        const remaining = try fbs.getPos();
        if (remaining != bytes.len - 4) return error.TrailingBytes;
    }
    return v;
}

pub fn encodeAlloc(allocator: std.mem.Allocator, value: Value) ![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);

    try list.appendSlice(allocator, "ODM1");
    try encodeValue(allocator, &list, value);

    return try list.toOwnedSlice(allocator);
}

pub fn validateCanonical(bytes: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    _ = try decodeAlloc(arena.allocator(), bytes, .{ .require_canonical = true });
}

fn decodeValueAlloc(allocator: std.mem.Allocator, r: anytype, opts: DecodeOptions) !Value {
    const tag_u8 = try r.readByte();
    const tag: Tag = @enumFromInt(tag_u8);

    const len = try readVarintU64(allocator, r, opts.require_canonical);
    // Read payload into temp buffer for structured parsing
    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    try r.readNoEof(buf);

    var fbs = std.io.fixedBufferStream(buf);
    var pr = fbs.reader();

    const v = switch (tag) {
        .null => blk: {
            if (len != 0) return error.BadNull;
            break :blk Value{ .null = {} };
        },
        .bool => blk: {
            if (len != 1) return error.BadBool;
            const b = try pr.readByte();
            if (b != 0 and b != 1) return error.BadBool;
            break :blk Value{ .bool = (b == 1) };
        },
        .uint => blk: {
            const u = try readVarintU64(allocator, pr, opts.require_canonical);
            // canonical: payload must be entirely consumed
            if (opts.require_canonical and (try fbs.getPos()) != len) return error.NonCanonical;
            break :blk Value{ .uint = u };
        },
        .int => blk: {
            const u = try readVarintU64(allocator, pr, opts.require_canonical);
            if (opts.require_canonical and (try fbs.getPos()) != len) return error.NonCanonical;
            const i = zigzagDecode(u);
            break :blk Value{ .int = i };
        },
        .bytes => Value{ .bytes = buf },
        .string => blk: {
            if (!std.unicode.utf8ValidateSlice(buf)) return error.BadUtf8;
            break :blk Value{ .string = buf };
        },
        .array => blk: {
            const count = try readVarintU64(allocator, pr, opts.require_canonical);
            var items = try allocator.alloc(Value, count);
            errdefer allocator.free(items);

            var idx: usize = 0;
            while (idx < count) : (idx += 1) {
                items[idx] = try decodeValueAlloc(allocator, pr, opts);
            }
            if (opts.require_canonical and (try fbs.getPos()) != len) return error.TrailingBytes;
            break :blk Value{ .array = items };
        },
        .map => blk: {
            const count = try readVarintU64(allocator, pr, opts.require_canonical);
            var entries = try allocator.alloc(MapEntry, count);
            errdefer allocator.free(entries);

            var prev_key: ?[]const u8 = null;

            var idx: usize = 0;
            while (idx < count) : (idx += 1) {
                const key_val = try decodeValueAlloc(allocator, pr, opts);
                if (key_val != .string) return error.BadMapKey;
                const key = key_val.string;

                if (prev_key) |pk| {
                    const cmp = std.mem.order(u8, pk, key);
                    if (cmp != .lt) return error.MapKeyOrder; // must be strictly increasing
                }
                prev_key = key;

                const val = try decodeValueAlloc(allocator, pr, opts);
                entries[idx] = .{ .key = key, .value = val };
            }
            if (opts.require_canonical and (try fbs.getPos()) != len) return error.TrailingBytes;
            break :blk Value{ .map = entries };
        },
    };

    // For bytes/string we intentionally keep buf ownership in the returned Value.
    // For other types, buf is unused and can be freed.
    switch (tag) {
        .bytes, .string => {},
        else => allocator.free(buf),
    }

    return v;
}

fn encodeValue(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), value: Value) !void {
    switch (value) {
        .null => try encodeTLV(allocator, out, .null, &[_]u8{}),
        .bool => |b| {
            var payload: [1]u8 = .{ if (b) 1 else 0 };
            try encodeTLV(allocator, out, .bool, payload[0..]);
        },
        .uint => |u| {
            var tmp: std.ArrayListUnmanaged(u8) = .{};
            defer tmp.deinit(allocator);
            try writeVarintU64(allocator, &tmp, u);
            try encodeTLV(allocator, out, .uint, tmp.items);
        },
        .int => |i| {
            var tmp: std.ArrayListUnmanaged(u8) = .{};
            defer tmp.deinit(allocator);
            try writeVarintU64(allocator, &tmp, zigzagEncode(i));
            try encodeTLV(allocator, out, .int, tmp.items);
        },
        .bytes => |b| try encodeTLV(allocator, out, .bytes, b),
        .string => |s| {
            if (!std.unicode.utf8ValidateSlice(s)) return error.BadUtf8;
            try encodeTLV(allocator, out, .string, s);
        },
        .array => |arr| {
            var tmp: std.ArrayListUnmanaged(u8) = .{};
            defer tmp.deinit(allocator);
            try writeVarintU64(allocator, &tmp, arr.len);
            for (arr) |it| try encodeValue(allocator, &tmp, it);
            try encodeTLV(allocator, out, .array, tmp.items);
        },
        .map => |entries| {
            // Canonical rule: keys must be sorted and unique.
            // The encoder enforces this by requiring strict order.
            var tmp: std.ArrayListUnmanaged(u8) = .{};
            defer tmp.deinit(allocator);
            try writeVarintU64(allocator, &tmp, entries.len);

            var prev: ?[]const u8 = null;
            for (entries) |e| {
                if (!std.unicode.utf8ValidateSlice(e.key)) return error.BadUtf8;
                if (prev) |pk| {
                    if (std.mem.order(u8, pk, e.key) != .lt) return error.MapKeyOrder;
                }
                prev = e.key;
                try encodeValue(allocator, &tmp, Value{ .string = e.key });
                try encodeValue(allocator, &tmp, e.value);
            }
            try encodeTLV(allocator, out, .map, tmp.items);
        },
    }
}

fn encodeTLV(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), tag: Tag, payload: []const u8) !void {
    try out.append(allocator, @intFromEnum(tag));
    try writeVarintU64(allocator, out, payload.len);
    try out.appendSlice(allocator, payload);
}

fn readVarintU64(allocator: std.mem.Allocator, r: anytype, require_canonical: bool) !u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    var bytes_read: usize = 0;

    while (true) : (bytes_read += 1) {
        const b = try r.readByte();
        const low = @as(u64, b & 0x7f);

        if (shift >= 64 and low != 0) return error.VarintOverflow;
        result |= (low << shift);

        const cont = (b & 0x80) != 0;
        shift += 7;

        if (!cont) break;

        if (bytes_read > 9) return error.VarintOverflow;
    }

    if (require_canonical) {
        // Reject non-canonical encodings: re-encode and compare.
        var tmp: std.ArrayListUnmanaged(u8) = .{};
        defer tmp.deinit(allocator);
        try writeVarintU64(allocator, &tmp, result);

        // We cannot directly compare because we do not have the original bytes here.
        // So we do an equivalent canonicality check:
        // If the value is small enough to fit in fewer bytes than bytes_read+1, encoding was not canonical.
        const canonical_len = tmp.items.len;
        const used_len = bytes_read + 1;
        if (used_len != canonical_len) return error.NonCanonicalVarint;
    }

    return result;
}

fn writeVarintU64(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), v: u64) !void {
    var x = v;
    while (true) {
        const byte = @as(u8, @intCast(x & 0x7f));
        x >>= 7;
        if (x == 0) {
            try out.append(allocator, byte);
            return;
        } else {
            try out.append(allocator, byte | 0x80);
        }
    }
}

fn zigzagEncode(i: i64) u64 {
    return (@as(u64, @bitCast(i)) << 1) ^ @as(u64, @bitCast(i >> 63));
}

fn zigzagDecode(u: u64) i64 {
    const tmp: i64 = @bitCast(u >> 1);
    const neg: i64 = @bitCast(@as(u64, 0) - (u & 1));
    return tmp ^ neg;
}


// ---- Pointer helpers ----
// ODM tooling uses JSON-pointer style paths for convenience.
// Supported: /a/b/c with ~0 and ~1 decoding rules.
// Arrays are not addressable by pointer in ODM v0.1 (maps only).

pub fn pointerGetValue(root: Value, ptr: []const u8) !?Value {
    if (ptr.len == 0) return root;
    if (ptr[0] != '/') return error.InvalidPointer;

    var cur = root;
    var it = std.mem.splitScalar(u8, ptr[1..], '/');

    while (it.next()) |raw| {
        const tok = try decodeJsonPointerTokenAlloc(std.heap.page_allocator, raw);
        defer std.heap.page_allocator.free(tok);

        switch (cur) {
            .map => |entries| {
                var found: ?Value = null;
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

    return cur;
}

pub fn pointerGetStringOrNull(root: Value, ptr: []const u8) !?[]const u8 {
    const v = try pointerGetValue(root, ptr) orelse return null;
    if (v != .string) return null;
    return v.string;
}

pub fn pointerIsIntOrUint(root: Value, ptr: []const u8) !bool {
    const v = try pointerGetValue(root, ptr) orelse return false;
    return v == .int or v == .uint;
}

fn decodeJsonPointerTokenAlloc(allocator: std.mem.Allocator, tok: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .{};
    errdefer out.deinit(allocator);

    var i: usize = 0;
    while (i < tok.len) : (i += 1) {
        const c = tok[i];
        if (c == '~') {
            if (i + 1 >= tok.len) return error.InvalidPointer;
            const n = tok[i + 1];
            if (n == '0') {
                try out.append(allocator, '~');
            } else if (n == '1') {
                try out.append(allocator, '/');
            } else return error.InvalidPointer;
            i += 1;
        } else {
            try out.append(allocator, c);
        }
    }
    return out.toOwnedSlice(allocator);
}
