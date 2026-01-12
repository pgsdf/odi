# ODI — Open Disk Image

ODI (Open Disk Image) is a deterministic, verifiable disk image **container format** designed for reproducible systems, immutable base images, and long-lived artifacts.

ODI is not an installer, package manager, or runtime.  
It is a **format** that cleanly separates:

- payload data
- structured metadata
- filesystem manifests
- cryptographic signatures

This separation allows policy, tooling, and trust models to evolve independently of the image format itself.

---

## Why ODI exists

Many existing image formats solve adjacent but different problems:

- **ISO** targets optical media and boot loaders
- **DMG** is Apple-specific and not an open standard
- **AppImage** focuses on application distribution
- **OCI** assumes container runtimes and layered execution

ODI focuses on a different problem space:

- reproducible system images
- immutable base layers
- verifiable artifacts
- snapshot-oriented filesystems
- long-term archival and auditability

ODI prioritizes **determinism, explicit verification, and clarity over convenience**.

---

## Design principles

- Deterministic by construction  
- Explicit mutation, never implicit  
- Stable bytes over clever abstractions  
- Verification without trust assumptions  
- Signatures without embedded policy  
- Canonical metadata  

ODI intentionally avoids workflow, installer, or governance decisions.

---

## High-level format overview

An ODI file consists of:

1. **Header**  
   Identifies the container and describes layout.

2. **Section table**  
   Authoritative map of all sections, offsets, lengths, and hashes.

3. **Section payloads**
   - `payload` — filesystem or dataset image (SquashFS today, ZFS planned)
   - `meta` — canonical JSON metadata
   - `manifest` — filesystem inventory and content hashes
   - `sig` — optional detached signature

Each section is hashed independently and can be verified without trusting other sections.

---

## Reference implementation

This repository contains the **reference implementation** of ODI:

- Language: **Zig 0.15.2**
- Style: conservative, readable, streaming-oriented
- Focus:
  - structural correctness
  - minimal allocations
  - deterministic output
  - clear failure modes

The reference implementation is **informative**, not normative.  
The specifications define the format.

---

## Status

Current state:

- ODI container format: **stable**
- META canonicalization: **complete**
- MANIFEST and tree verification: **complete**
- Detached signatures: **complete**
- SquashFS payloads: **supported**
- ZFS payloads: **in progress**

See `docs/ROADMAP.md` for planned work.

---

## Documentation

All documentation lives under `docs/`.

### Specifications
- **Living specification:** `docs/SPECIFICATION.md`
- **Frozen normative spec:** `docs/ODI-0.1.md`
- **Format notes:** `docs/ODI_SPEC.md`

### Guides
- **CLI reference:** `docs/COMMANDS.md`
- **META rules:** `docs/META.md`
- **Signing model:** `docs/SIGNING.md`

### Contributor documentation
- **Architecture:** `docs/ARCHITECTURE.md`
- **How to implement ODI:** `docs/HOW_TO_IMPLEMENT_ODI.md`
- **Test vectors:** `tests/vectors/`

Start with `docs/README.md` for an index.

---

## What ODI is *not*

ODI deliberately does **not** aim to be:

- a package manager
- an installer framework
- a distribution governance system
- a runtime execution model
- a policy engine

Those concerns belong **outside** the container format.

---

## License

BSD 2-Clause License  
Copyright © 2026  
Pacific Grove Software Distribution Foundation

See `LICENSE.md`.

---

## Project

- Repository: https://github.com/pgsdf/odi
- Organization: Pacific Grove Software Distribution Foundation

ODI is a format, not a platform.  
Policy belongs outside the container.

