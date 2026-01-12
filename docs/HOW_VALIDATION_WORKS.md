# How validation works

ODI uses an axioms, invariants, artifacts model.

- Axioms define what an ODI is.
- Invariants are the concrete checks that enforce axioms.
- Artifacts are immutable outputs. Tools derive new artifacts, they do not edit in place.

This document explains how validation is performed by the reference implementation.

## The validation gate

All commands that consume an ODI artifact must route through a shared validation gate.

The reference implementation exposes this gate as:

- `odi validate <file.odi>`
- `odi verify <file.odi>` (calls the same validation gate first)

Validation fails closed. If any check fails, the artifact is rejected.

## What is validated

Validation is intentionally layered.

### 1. Container structure, Axiom 2

The container is validated first:

- header magic and version
- section table bounds
- section entry bounds within file size
- no overlapping sections
- reserved fields are zero
- hash algorithm and lengths are consistent

If structure is wrong, validation stops immediately.

### 2. Section hashing, Axiom 3

Each section is verified independently:

- the hash input is exactly the section payload bytes
- hash verification does not depend on parsing other sections

Any hash mismatch invalidates the entire artifact.

### 3. Metadata canonicalization, Axiom 4

Metadata is validated as canonical.

If `meta_bin` is present:

- metadata is ODM encoded
- ODM canonical rules are enforced
  - canonical varints
  - valid UTF 8 strings
  - strictly increasing, unique map keys
  - no trailing bytes

If `meta_bin` is not present, validation falls back to JSON META:

- META must parse as JSON
- canonicalization must produce identical bytes
- non canonical META is rejected

### 4. Signature structure, Axiom 6

Signatures may be present.

Validation checks only structure:

- signature section payload is well formed
- signature payload is valid UTF 8
- optional require signature mode can enforce presence

Validation does not enforce trust policy. Trust is external.

## What validation does not do

Validation does not:

- install anything
- execute anything
- define trust policy
- decide which keys are trusted
- infer intent from malformed input

ODI is strict by design.

## Test vectors and regression protection

ODI includes positive and negative test vectors in `tests/vectors`.

- passing vectors must succeed
- failing vectors must fail

`make verify` runs the validator over all vectors and enforces this contract.

End of document.
