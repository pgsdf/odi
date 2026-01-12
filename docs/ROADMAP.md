# ODI Roadmap

This roadmap describes the planned evolution of the Open Disk Image (ODI) format, its specifications, and the reference implementation.

ODI is guided by axioms, invariants, and artifacts.
The roadmap reflects stability of truths first, and expansion of tooling second.

Dates are indicative. Completion is gated by correctness, not time.

## Guiding principles

- Axioms are stable
- Specifications precede implementation
- Artifacts are immutable
- Validation fails closed
- Backward compatibility is explicit, never implicit

## Completed milestones

### ODI 0.1 foundation

- ODI container format defined
- Header and section table finalized
- Independent section hashing
- Canonical JSON META
- Manifest semantics defined
- Detached signature model
- Explicit axioms defined in spec
- Validation rules mapped to axioms
- Negative test vectors per axiom
- Reference implementation in Zig 0.15.2

Status: Frozen and stable.

### ODM 1.0

- ODM binary metadata specification
- Canonical TLV encoding
- Canonical varints
- Strict map key ordering
- UTF 8 enforcement
- Reference implementation in Zig
- meta_bin section type added
- Validation integrated with ODI validator
- Positive and negative ODM test vectors

Status: Draft complete, ready for real use.

### Zig 0.15 migration (January 2026)

Comprehensive update of the reference implementation to Zig 0.15.x.

Major API changes addressed:

- Build system: `root_source_file` renamed to `root`, `LazyPath` to `Build.LazyPath`
- I/O system: `File.reader()`/`writer()` now require explicit buffers, use `writeAll()` directly
- Collections: `ArrayList` removed `init()`, migrated to `ArrayListUnmanaged` pattern
- JSON: `std.json.stringify()` removed, using `std.json.Stringify` struct with writer API
- JSON: `std.json.fmtString()` removed, using custom `writeJsonString()` function
- JSON: `std.json.Value` gained `.number_string` variant requiring switch coverage
- Random: `std.rand` renamed to `std.Random`
- Filesystem: `File.Stat` no longer exposes `uid`/`gid`/`mtime`, using `std.posix.fstatat`
- Filesystem: `Dir.readLink()` returns slice directly instead of length
- Module system: stricter enforcement, files cannot belong to multiple modules
- Type system: stricter const/var enforcement for method receivers

Total: 34 pull requests merged.

Status: Complete. All compilation errors resolved.

## Near term milestones

### ODI 0.1.1 maintenance

Focus: stability, not features.

- Fix bugs found via test vectors
- Harden validation error messages and axiom named failures
- Improve CLI diagnostics
- Expand documentation clarity
- Add CI validation against test vectors

No format changes.

### SquashFS payload hardening

Focus: determinism and reproducibility.

- Document deterministic SquashFS build requirements
- Provide reference mksquashfs flags
- Add test payload vectors
- Validate payload hash stability across rebuilds

This does not change the ODI format.

## Medium term milestones

### ODI 0.2 planned

Focus: replacing JSON authority, not breaking users.

Key changes:

- meta_bin, ODM, becomes the preferred metadata encoding
- JSON meta becomes optional or deprecated in 0.2
- Axiom 4 strengthened via typed binary metadata
- Canonical metadata enforced structurally, not textually

Compatibility:

- ODI 0.1 remains valid
- ODI 0.2 tooling may optionally read ODI 0.1
- Conversion tooling is explicit

Status: Spec work required before implementation.

### Manifest evolution

Focus: stronger invariants without scope creep.

- Optional binary manifest format, future
- Stronger inventory invariants
- Explicit symlink and permission modeling
- Clear rules for manifest vs payload trust boundaries

No policy enforcement.

## Long term milestones

### ZFS native payloads

Focus: native alignment with PGSD goals.

- ZFS send stream payloads
- Snapshot identity preservation
- Dataset layout description in metadata
- Optional incremental payload semantics

ODI remains payload agnostic.

### Extended verification tooling

- Cross implementation verification harness
- Offline artifact audit tooling
- Provenance explanation commands
- Human readable explain output, why an artifact is valid

## Explicit non goals

ODI will not become:

- A package manager
- An installer framework
- A runtime execution system
- A policy engine
- A governance mechanism

Those concerns belong outside the container format.

## Decision process

Changes to axioms or format require:

1. Written specification changes
2. Test vectors, positive and negative
3. Reference implementation updates
4. Explicit versioning

No silent changes.

## Summary

ODI is intentionally conservative.

Truths are defined once.
Enforcement is strict.
Evolution is explicit.
Artifacts are long lived.
