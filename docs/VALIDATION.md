# Validation and invariants

ODI uses an axioms, invariants, artifacts approach.

Axioms are the truths that define what an ODI is.
Invariants are the concrete checks that enforce axioms.
Artifacts are immutable outputs. Tools derive new artifacts, they do not edit in place.

This document maps axioms to invariant checks in the reference implementation.

## Axiom 1, determinism

Invariant checks:

- Input enumeration is sorted, paths are processed in stable order
- META is canonicalized on write
- MANIFEST is emitted in stable order
- Section table entries are emitted in a stable order
- Reserved fields are zeroed

Typical failures:

- Unsorted file traversal
- Non canonical META bytes
- Unstable timestamp fields included in META or MANIFEST

## Axiom 2, section authority

Invariant checks:

- Header magic and version
- Section table bounds
- Each section offset and length is within file bounds
- Sections do not overlap
- Reserved fields are zero

Typical failures:

- Out of bounds section offsets
- Overlapping sections
- Malformed table length

## Axiom 3, independent verification

Invariant checks:

- Each section hash is computed over exactly that section payload bytes
- Hash verification does not depend on parsing other sections

Typical failures:

- Hash mismatch
- Hash algorithm id not supported

## Axiom 4, canonical metadata

Invariant checks:

- META parses as JSON
- Canonicalization produces a byte identical result when applied to META
- META bytes are the canonical encoding

Typical failures:

- META contains whitespace differences, key order differences, or alternate number spellings that are not canonical

## Axiom 5, explicit immutability

Invariant checks:

- Commands that change ODI content require an output path
- Tools never write in place
- Signature invalidation is explicit, for example via strip signature options

Typical failures:

- Attempted in place mutation

## Axiom 6, policy exclusion

Invariant checks:

- Signature section structure is validated when present
- Trust decisions require external inputs

Typical failures:

- Malformed signature payload

## Axiom 7, artifact identity

Invariant checks:

- Equality is defined by byte identity
- Tools treat file paths as labels only

## Where validation happens

All commands route through shared validation routines:

- validateContainer, structural checks
- validateMeta, META canonical checks
- validateManifest, MANIFEST schema and ordering checks
- validateSignature, signature structure checks

End of document.
