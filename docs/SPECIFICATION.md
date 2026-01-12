# ODI Specification
Open Disk Image (ODI)

Version: 0.1  
Status: Draft  
License: BSD 2-Clause  
Copyright © 2026  
Pacific Grove Software Distribution Foundation

## 1. Scope

This document defines the Open Disk Image (ODI) file format.

ODI is a deterministic, verifiable container format for disk images and filesystem payloads. This specification defines on disk structures, canonicalization rules, hashing, and signature semantics. It does not define installation behavior, execution semantics, or policy.

## 2. Design goals

ODI is designed to:

- Be deterministic by construction
- Enable independent verification of all components
- Separate data, metadata, and policy
- Support immutable and reproducible system images
- Remain implementation agnostic

## 3. Terminology

- Container: the ODI file as a whole
- Section table: the list of section descriptors
- Section payload: the raw bytes referenced by a section descriptor
- Verifier: a tool that validates hashes and optional signatures

## 4. Byte order and encoding

- All integers are little endian
- Strings are UTF 8
- JSON is UTF 8

## 5. High level file structure

An ODI file consists of three logical regions:

1. Header
2. Section table
3. Section payloads

## 6. Binary layout diagram

```
+----------------------------------------------------+
| ODI Header                                         |
+----------------------------------------------------+
| Section Table                                      |
+----------------------------------------------------+
| Section Payloads                                   |
+----------------------------------------------------+
```

A more detailed view:

```
+----------------------------------------------------+
| Header (56 bytes)                                  |
|----------------------------------------------------|
| magic            4 bytes   "ODI1"                   |
| version          u16       1                        |
| section_count    u16       number of entries        |
| table_offset     u64       usually 56               |
| table_length     u64       section_count * 96       |
| reserved         32 bytes  zero                      |
+----------------------------------------------------+
| Section Table (section_count entries, 96 bytes each)|
|----------------------------------------------------|
| Section[0]                                         |
| Section[1]                                         |
| ...                                                |
| Section[N-1]                                       |
+----------------------------------------------------+
| Section payload bytes                              |
|----------------------------------------------------|
| payload                                            |
| meta                                               |
| manifest                                           |
| sig (optional)                                     |
+----------------------------------------------------+
```

Notes:

- Section order in the payload region is defined by offsets in the section table
- Sections may appear in any order physically
- Sections must not overlap
- The section table is authoritative

## 7. Header

### 7.1 Header fields

Header size is 56 bytes.

| Field | Type | Size | Meaning |
| --- | --- | --- | --- |
| magic | u8[4] | 4 | Must be "ODI1" |
| version | u16 | 2 | Must be 1 for ODI 0.1 |
| section_count | u16 | 2 | Number of section entries |
| table_offset | u64 | 8 | Absolute file offset of section table |
| table_length | u64 | 8 | Byte length of section table |
| reserved | u8[32] | 32 | Must be zero in ODI 0.1 |

### 7.2 Header validation

A reader must reject the file if:

- magic is not "ODI1"
- version is not 1
- table_offset is less than header size
- table_length is not an integer multiple of section entry size
- section_count does not match table_length divided by entry size

## 8. Section table

### 8.1 Section entry fields

Each section entry uses C layout and is 96 bytes.

| Field | Type | Size | Meaning |
| --- | --- | --- | --- |
| stype | u32 | 4 | Section type identifier |
| reserved0 | u32 | 4 | Must be zero |
| offset | u64 | 8 | Absolute file offset of section payload |
| length | u64 | 8 | Length in bytes of section payload |
| hash_alg | u8 | 1 | Hash algorithm identifier |
| hash_len | u8 | 1 | Number of bytes used from hash field |
| reserved1 | u16 | 2 | Must be zero |
| hash | u8[64] | 64 | Hash bytes, first hash_len bytes are used |
| padding | u8[4] | 4 | C layout tail padding, must be zero |

### 8.2 Section type identifiers

ODI 0.1 defines:

| Name | Value |
| --- | --- |
| payload | 1 |
| meta | 2 |
| manifest | 3 |
| sig | 4 |

### 8.3 Hash algorithm identifiers

ODI 0.1 requires SHA 256.

| Name | Value | Digest size |
| --- | --- | --- |
| sha256 | 1 | 32 |

Rules:

- hash_len must be 32 for sha256
- the first 32 bytes of hash must match the SHA 256 digest of the section payload bytes
- remaining hash bytes must be zero in ODI 0.1

## 9. Section types

### 9.1 payload

The payload section is opaque to ODI.

The payload may contain a SquashFS image, a raw filesystem image, or a ZFS dataset stream. Payload interpretation belongs to tooling layered above ODI.

### 9.2 meta

META is a single JSON document.

META must be canonicalized before hashing and writing.

Canonicalization rules:

1. UTF 8 encoding
2. Minified JSON
3. Object keys sorted lexicographically at every level
4. Arrays preserve order
5. Deterministic number formatting
6. Standard JSON escaping
7. No trailing newline

### 9.3 manifest

The manifest is a structured inventory describing filesystem contents. It is payload agnostic.

### 9.4 sig

The sig section is optional.

Signatures are detached and policy free.

## 10. Signing payload

ODI defines a deterministic signing payload called ODI SIG V1.

It is a UTF 8 text block with stable line order. Each line includes the section name, hash algorithm, and digest.

Example structure:

```
ODI-SIG-V1
payload sha256 <hex>
meta sha256 <hex>
manifest sha256 <hex>
sig missing
```

If a section is absent, the value must be `missing`.

## 11. Verification requirements

A verifier must:

- parse the header and section table
- validate section boundaries and non overlap
- compute and compare section hashes
- optionally verify signature, using external trust material

## 12. Compatibility rules

- ODI 0.1 readers must reject version numbers other than 1
- extensions must add new section types, existing semantics must not be redefined

## 13. Non goals

ODI does not define:

- installation behavior
- boot mechanisms
- runtime execution
- package management
- trust policy

End of document.
