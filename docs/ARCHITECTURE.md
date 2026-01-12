# ODI Architecture

This document explains how the repository is organized and how the reference implementation is structured.

## Repository layout

- src
  - main.zig
    - CLI entry point
    - argument parsing
    - command routing
  - odi.zig
    - ODI container parsing and validation
    - section hashing and verification
    - META read and rewrite logic
    - manifest parsing and diff logic
- docs
  - ODI_SPEC.md
    - format notes and project documentation
  - META.md
    - META semantics and canonicalization rules
  - SIGNING.md
    - signing model and workflow
  - COMMANDS.md
    - CLI reference
- tests
  - vectors
    - small ODI files and expected outputs for cross implementation testing

## Data flow

Typical operations follow this pattern:

1. Parse header and section table
2. Validate structure
   - table bounds
   - section bounds
   - non overlap
3. Perform the requested operation
   - verify hashes
   - read META
   - diff manifests
   - rewrite META
4. Write results
   - text output or JSON output
   - new ODI file when rewriting

## Determinism strategy

Determinism is a core goal.

- Hashes are computed over exact byte ranges referenced by the section table
- META is canonical JSON, written in a stable form
- Signing uses a deterministic payload derived from section hashes

## Mutation model

ODI is treated as immutable.

Operations that change content always write a new output file.

Examples:

- meta set writes a new file and optionally strips the existing signature
- meta patch writes a new file and optionally strips the existing signature

This keeps verification semantics simple and reduces accidental trust bugs.

## Security model

ODI does not embed trust policy.

- verify checks hashes always
- verify checks signatures only when asked, and only using externally provided trust material

## Extensibility

The recommended way to extend ODI is to add new section types.

Existing types should keep their meaning stable.

End of document.
