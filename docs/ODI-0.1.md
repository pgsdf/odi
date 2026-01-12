# ODI 0.1
Open Disk Image (ODI) Specification

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
