# ODI Spec (draft)

ODI is a container format for disk-image class payloads (SquashFS, raw file systems such as ZFS send streams, etc.).
This repo includes a reference implementation and the initial verification and signing model.

## Design goals

- Deterministic, auditable artifacts
- Separation of content from policy
- Fast integrity checks via section hashes
- Optional signatures, based on a deterministic signing payload derived from section hashes

## Sections

ODI contains a header, a section table, and N sections.

Recommended section types:
- payload
- meta (canonical JSON)
- manifest (canonical JSON)
- sig (detached signature bytes)

## Signing payload

The signature is computed over the following canonical bytes:

```
ODI-SIG-V1
payload <alg> <hex>|missing
meta <alg> <hex>|missing
manifest <alg> <hex>|missing
```

This ties the signature to the intended artifact content without depending on physical offsets.


## META section JSON canonicalization

ODI requires the META section to be a single UTF 8 JSON document that is canonicalized before writing.

Canonicalization rules

1. Encoding is UTF 8
2. Output JSON is minified with no insignificant whitespace
3. Object keys are sorted lexicographically by raw UTF 8 bytes at every object level
4. Arrays keep their original order
5. Strings use JSON escaping for control characters, quotes, and backslash
6. Numbers are serialized deterministically so the same semantic value yields the same bytes
7. The META section contains exactly those canonical JSON bytes, with no trailing newline

Rationale

This makes META hashes stable and makes signatures stable when they cover META hashes.

## Versioned specification

The frozen normative specification for version 0.1 is `ODI-0.1.md` in this docs directory.
