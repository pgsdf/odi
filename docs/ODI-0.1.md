# ODI 0.1
Open Disk Image (ODI) Specification

The keywords must, must not, should, and may are normative in this document.


Status: Stable  
Version: 0.1  
Date: 2026  
License: BSD 2-Clause  
Copyright © 2026  
Pacific Grove Software Distribution Foundation

## 1. Conformance

An implementation conforms to ODI 0.1 if it:

- parses the ODI header and section table
- enforces all validation requirements in this specification
- verifies section hashes as defined
- treats META as canonical JSON
- does not reinterpret or redefine section meaning

This document is normative. The reference implementation is informative.


## ODI axioms

This section defines the axioms that constitute the Open Disk Image (ODI) format.

These axioms are not features, guidelines, or recommendations.
They are truths that must hold for a file to be considered a valid ODI 0.1 artifact.

Any implementation that produces or accepts an ODI must enforce these axioms.
If any axiom is violated, the artifact must be rejected.

### Axiom 1: Determinism

Given the same semantic inputs, an ODI writer must produce identical bytes.

Implications:

- Section ordering must be deterministic
- Metadata serialization must be canonical
- No nondeterministic inputs, such as timestamps, random identifiers, or unstable filesystem enumeration order, may affect output bytes
- Two independently generated ODI artifacts from identical inputs must be byte for byte identical

### Axiom 2: Section authority

The section table is the sole authoritative description of the container layout.

Implications:

- All section offsets, lengths, and hashes are defined exclusively by the section table
- Bytes outside the section table described section bounds must not be trusted
- Sections must not overlap
- Physical ordering of section payloads is irrelevant, only the section table defines meaning

### Axiom 3: Independent verification

Each section must be verifiable independently of all other sections.

Implications:

- The hash of a section covers only that section payload bytes
- Verification of one section must not require trusting or parsing another section
- Failure to verify any section invalidates the entire artifact

### Axiom 4: Canonical metadata

The META section has exactly one valid encoding for a given semantic value.

Implications:

- META must be canonicalized before hashing and writing
- Semantically equivalent metadata must produce identical META bytes
- Non canonical META encoding must cause the artifact to be rejected

### Axiom 5: Explicit immutability

ODI artifacts are immutable.

Implications:

- Any operation that changes ODI semantics must produce a new artifact
- In place mutation of an ODI artifact is forbidden
- Tools must not silently modify existing artifacts

### Axiom 6: Policy exclusion

ODI defines structure and verification, not trust policy.

Implications:

- Signatures may be present, but trust decisions are external to the format
- An ODI artifact must not encode trust policy, key trust, or enforcement rules
- Signature structure must be validated even if trust is not enforced

### Axiom 7: Artifact identity

An ODI artifact is defined by its bytes.

Implications:

- Two artifacts with identical bytes are identical artifacts
- Two artifacts with differing bytes are distinct artifacts, regardless of intent
- Artifact identity does not depend on filenames, locations, or external context

## Axiom enforcement

All ODI implementations must enforce these axioms during:

- artifact creation
- artifact verification
- artifact inspection
- artifact derivation

If any axiom fails, processing must fail closed.

An artifact that violates any axiom is not an ODI 0.1 artifact.



## 2. Encoding and byte order

- All integers are little endian
- Strings are UTF 8
- JSON is UTF 8

## 3. File layout

An ODI 0.1 file consists of:

1. Header (56 bytes)
2. Section table (section_count entries, 96 bytes each)
3. Section payloads (byte ranges referenced by the section table)

All offsets are absolute from the start of the file.

## 4. Header

### 4.1 Header fields

| Field | Type | Size | Requirements |
| --- | --- | --- | --- |
| magic | u8[4] | 4 | Must equal "ODI1" |
| version | u16 | 2 | Must equal 1 |
| section_count | u16 | 2 | Must match section table entry count |
| table_offset | u64 | 8 | Must be at least 56 |
| table_length | u64 | 8 | Must be section_count * 96 |
| reserved | u8[32] | 32 | Must be zero |

### 4.2 Header validation

A reader must reject the file if any header requirement is not met.

## 5. Section table

### 5.1 Section entry fields

Each section entry is 96 bytes.

| Field | Type | Size | Requirements |
| --- | --- | --- | --- |
| stype | u32 | 4 | Must be a known or extension type |
| reserved0 | u32 | 4 | Must be zero |
| offset | u64 | 8 | Must be within file bounds |
| length | u64 | 8 | Must not exceed file bounds |
| hash_alg | u8 | 1 | Must be 1 for sha256 in ODI 0.1 |
| hash_len | u8 | 1 | Must be 32 for sha256 |
| reserved1 | u16 | 2 | Must be zero |
| hash | u8[64] | 64 | First 32 bytes are sha256 digest, remaining bytes must be zero |
| padding | u8[4] | 4 | Must be zero |

### 5.2 Table validation

A reader must reject the file if:

- any section overlaps another section
- any section extends past end of file
- table_length is not an integer multiple of 96
- reserved fields are not zero

## 6. Section types

ODI 0.1 defines the following section type identifiers:

| Name | Value |
| --- | --- |
| payload | 1 |
| meta | 2 |
| manifest | 3 |
| sig | 4 |

## 7. Hashing

### 7.1 Required algorithm

ODI 0.1 requires SHA 256.

hash_alg must be 1 and hash_len must be 32 for all sections.

### 7.2 Hash input

The hash input is exactly the section payload bytes referenced by offset and length.

The hash does not include header or table bytes.

## 8. META canonicalization

META is a single JSON document and must be canonicalized before hashing.

Canonicalization rules:

1. UTF 8 encoding
2. Minified JSON
3. Object keys sorted lexicographically at every level
4. Arrays preserve order
5. Deterministic number formatting
6. Standard JSON escaping
7. No trailing newline

Two META documents that are semantically equal must produce identical byte streams after canonicalization.

## 9. Signing

### 9.1 Signature payload

ODI 0.1 defines ODI SIG V1 signing payload as UTF 8 text:

- first line is `ODI-SIG-V1`
- subsequent lines are in fixed order: payload, meta, manifest, sig
- each line is either:
  - `<name> sha256 <hex>`
  - `<name> missing`

### 9.2 Signature semantics

- Signatures are optional
- Modifying any section invalidates the signature
- Signature verification depends on external trust material

## 10. Compatibility

ODI 0.1 readers must reject files with version not equal to 1.

Extensions must add new section types. Existing section semantics must not be redefined.

## 11. Non goals

ODI 0.1 does not define:

- installation behavior
- boot mechanisms
- runtime execution
- package management
- trust policy

End of ODI 0.1 specification.


## Manifest semantics

The manifest is a JSON document.

ODI 0.1 defines a minimal manifest shape that verifiers may rely on.

### Minimal schema

The manifest root must be an object with an `entries` field.

`entries` must be an array of objects. Each entry object must contain:

- `path`, a UTF 8 string
- `kind`, a UTF 8 string, one of: file, dir, symlink
- `sha256`, optional, a lowercase hex string of 64 characters, required for kind file

Unknown fields must be ignored.

### Ordering

For deterministic output, writers must emit entries in lexicographic order by path.
Verifiers should accept any order, but may provide a warning when order is not canonical.

### Path rules

Paths are relative.
Paths must not contain NUL.
Paths must not contain `..` segments.


## Manifest schema

The `manifest` section is JSON with this shape:

- Top level object with key `entries`
- `entries` is an array of objects
- Each entry has required keys:
  - `path` (string, non empty)
  - `kind` (string): one of `file`, `dir`, `symlink`

Optional keys (when present, they must have the correct type):

- `sha256` (string, 64 lower case hex) for `file`
- `size` (integer, >= 0)
- `mode` (integer)
- `uid` (integer)
- `gid` (integer)
- `mtime` (integer, seconds since epoch)
- `target` (string) required for `symlink`

Duplicate `path` entries are invalid.

### check tree semantics

`odi manifest check-tree` compares a filesystem tree against the manifest:

- Any filesystem path not present in the manifest is reported as `extra`
- Any manifest path not found in the filesystem tree is reported as `missing`
- If both exist, the tool compares the fields that are present in the manifest entry:
  - `kind` must match
  - `size`, `mode`, `uid`, `gid`, `mtime` are compared when present
  - `sha256` is compared for files when present and when run in content mode
  - `target` is compared for symlinks when present


## Payload formats

The `payload` section is opaque bytes. A common payload is a read-only filesystem image such as SquashFS. If you claim determinism for a SquashFS payload, follow `docs/SQUASHFS.md`.
