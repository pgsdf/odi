# ODI (Open Disk Image) — reference implementation

This repository is a Zig 0.15.2 reference implementation for the ODI container work we have been defining.

## What is implemented in this drop

- ODI container parsing: header + section table
- Section hash verification (sha256)
- Manifest operations
  - `odi manifest dump`
  - `odi manifest diff` (basic, with content-only mode and limit/fail-fast semantics)
  - `odi manifest hash`
  - `odi manifest attest` (section-hash based)
- Signing
  - `odi sign` creates a new ODI with a `sig` section
  - `odi verify` can verify a signature with `ssh-keygen -Y verify`

## What is stubbed in this drop

(Updated: meta, provenance, and check-tree are now implemented in the ZIP created on 2026-01-11.)


- `odi manifest provenance` now implemented (minimal META extraction)
- `odi meta ...` now implemented (get/set/patch)
- `odi manifest check-tree` now implemented (basic content check for files)

These are all in the prior design plan and can be filled in next.

## Build

```sh
zig build
./zig-out/bin/odi help
```

## Verify

```sh
./zig-out/bin/odi verify --verify-hashes your.odi
```

## Sign

```sh
./zig-out/bin/odi sign base.odi --out base.signed.odi --key ~/.ssh/id_ed25519 --identity you@example.com
```

## Verify signature

```sh
./zig-out/bin/odi verify --verify-hashes --require-signature --allowed-signers allowed_signers --identity you@example.com base.signed.odi
```

## META canonicalization

The reference implementation writes META as canonical JSON so META hashes and signatures are stable. See docs/META.md.

## Signing

See docs/SIGNING.md.

## Specification

- docs/SPECIFICATION.md
- docs/ODI-0.1.md

## Contributor docs

- docs/ARCHITECTURE.md
- docs/HOW_TO_IMPLEMENT_ODI.md
- tests/vectors
