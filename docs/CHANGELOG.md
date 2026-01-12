# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Changed

- **Zig 0.15 Migration** - Complete rewrite of build system and standard library usage for Zig 0.15.x compatibility (34 PRs merged)

#### Build System
- Renamed `root_source_file` to `root` in build.zig
- Changed `LazyPath` to `Build.LazyPath`
- Added proper module dependencies for `odi`, `validate`, and `odm` modules

#### I/O System
- Replaced `File.reader()`/`writer()` with direct `writeAll()` calls (Zig 0.15 requires explicit buffers)
- Updated all file I/O operations to use new API patterns

#### Collections
- Migrated from `ArrayList` to `ArrayListUnmanaged` throughout codebase
- All collection methods now require explicit allocator parameter
- Replaced `ArrayList.init(allocator)` with `ArrayListUnmanaged` empty initializer `.{}`

#### JSON API
- Replaced removed `std.json.stringify()` with `std.json.Stringify` struct + writer pattern
- Replaced removed `std.json.fmtString()` with custom `writeJsonString()` function
- Added handling for new `std.json.Value.number_string` variant in all switch statements
- Updated `StringifyOptions` to `Stringify.Options`

#### Standard Library
- Renamed `std.rand` to `std.Random`
- Updated `Dir.readLink()` usage (now returns slice directly instead of length)
- Added `std.posix.fstatat` usage for uid/gid/mtime (no longer in `File.Stat`)
- Added portable timespec field access (BSD uses `.sec`, Linux uses `.tv_sec`)

#### Type System
- Fixed const/var mismatches for struct method receivers requiring mutable pointers
- Added `sha256BytesPadded()` helper for 64-byte `Section.hash` field
- Removed non-existent `reserved2` field from Section initializations
- Fixed `Attestation.toJsonAlloc` to only use fields that exist in the struct
- Corrected `RewriteMetaBinSetOptions` field names (`pointer`, `value_text`)

#### Module System
- Made `odm` a shared module imported by both `odi` and `validate`
- Changed direct file imports to module imports where required
- Fixed module dependency graph to prevent "file belongs to multiple modules" errors

### Fixed

- Incorrect `DiffMode` enum comparison (struct, not enum)
- Slice type mismatches in `stripFloatTrailingZeros` return handling

## [0.1.0] - 2026-01-11

### Added

- Initial ODI container format implementation
- Header and section table parsing
- Section hash verification (SHA-256)
- Manifest operations: dump, diff, hash, attest
- Signing with `odi sign`
- Verification with `odi verify`
- META operations: get, set, patch
- Provenance extraction
- check-tree manifest validation
- ODM binary metadata support
- Canonical JSON output for stable hashes
- SSH key-based signature support via ssh-keygen
