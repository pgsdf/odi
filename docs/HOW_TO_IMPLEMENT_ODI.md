# How to implement ODI

This guide is for contributors who want to build a reader or verifier in another language.

## Minimal reader

A minimal reader must:

1. Read the first 56 bytes as the header
2. Validate magic and version
3. Read the section table using table_offset and table_length
4. Validate each section entry
   - reserved fields are zero
   - offset and length are within file bounds
   - sections do not overlap
5. For each section, compute sha256 over the section payload bytes and compare with the table digest

If all hashes match, the file is structurally valid.

## META handling

META is UTF 8 JSON.

- Readers may parse META as standard JSON
- Writers must canonicalize META before hashing and writing

Canonicalization rules are described in SPECIFICATION.md and ODI-0.1.md.

## MANIFEST handling

MANIFEST is JSON. The reference implementation expects an object with an `entries` array.

Implementations should treat unknown fields as ignored and should not fail on additional keys.

## Signing

Signatures are optional.

The verifier should:

- compute section hashes first
- build the ODI SIG V1 signing payload
- verify using an external trust mechanism

The reference implementation uses OpenSSH `ssh-keygen -Y`.

## Common pitfalls

- Do not hash the whole file
- Do not assume section order
- Do not treat META bytes as stable unless canonicalized
- Do not accept overlapping sections
- Do not trust SIG unless hashes are verified first

## Suggested milestones for new implementations

1. Hash verification only
2. META extraction
3. MANIFEST parsing
4. Signing payload construction
5. Signature verification

End of document.
