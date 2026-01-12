# ODM 1.0
Open Data Map (ODM) Specification

Status: Draft  
Version: 1.0  
Date: 2026  
License: BSD 2-Clause  
Copyright © 2026  
Pacific Grove Software Distribution Foundation

ODM is a canonical binary encoding used by ODI for typed metadata. It is designed to be small, deterministic, and easy to implement.

ODM is intended to replace JSON for ODI metadata storage. JSON may remain as an optional projection, but ODM bytes are authoritative when present.

## 1. Overview

An ODM payload is:

- magic: 4 bytes, ASCII `ODM1`
- root: one ODM value

ODM values are encoded as:

- type: u8
- length: varint (unsigned base 128, canonical)
- payload: `length` bytes

All integers are little endian only in the sense that varints are least significant group first.

## 2. Types

ODM 1.0 defines the following type tags.

| Name | Tag | Payload |
| --- | --- | --- |
| null | 0x00 | empty |
| bool | 0x01 | 1 byte, 0 or 1 |
| int | 0x02 | varint zigzag encoded |
| uint | 0x03 | varint unsigned |
| bytes | 0x04 | raw bytes |
| string | 0x05 | UTF 8 bytes |
| array | 0x06 | structured, see below |
| map | 0x07 | structured, see below |

ODM 1.0 does not include floating point numbers.

## 3. Varint encoding

Varints are unsigned base 128. Each byte uses:

- low 7 bits: data
- high bit: continuation

Canonical rule:

- The encoding MUST be the shortest possible encoding for the value.
- Encodings that include redundant zero continuation groups MUST be rejected.

## 4. Signed integers

Signed integers are encoded using ZigZag, then varint.

ZigZag mapping:

- encode: (n << 1) ^ (n >> 63)
- decode: (u >> 1) ^ -(u & 1)

This guarantees a single canonical encoding for each signed value.

## 5. Strings

String payload bytes MUST be valid UTF 8.

No normalization is applied. Canonical equivalence is defined by byte equality.

## 6. Arrays

Array payload is:

- count: varint
- values: `count` consecutive ODM values

Array order is significant and preserved.

## 7. Maps

Map payload is:

- count: varint
- entries: `count` pairs of (key, value)

Each key MUST be an ODM string value.

Canonical rules for maps:

- Keys MUST be unique.
- Keys MUST be sorted lexicographically by their UTF 8 byte sequence.
- Duplicate keys MUST be rejected.
- Out of order keys MUST be rejected.

## 8. Canonical encoding

A value is canonical if:

- varints are canonical
- strings are valid UTF 8
- maps are sorted with unique keys
- no extra padding bytes exist
- lengths exactly match payload sizes

## 9. ODI integration

ODI uses ODM bytes in a `meta_bin` section.

Rules:

- When `meta_bin` is present, its ODM bytes are authoritative metadata.
- Tools MUST validate ODM canonical encoding before accepting the artifact.
- Tools MUST NOT treat non canonical ODM as valid.

End of document.
