# ODI signing

ODI 0.1 validation checks signature structure only. Trust and signer policy are external to the format.

ODI supports optional signatures in a SIG section.

Signature payload

The reference implementation signs the canonical signing payload.

ODI SIG V1

The payload is a UTF 8 text block with a stable field order. It includes

1. ODI header fields needed for verification
2. Section table entries
3. The SHA 256 hash for each section payload

Why META canonicalization matters

If META bytes are not canonical, the META hash can change even when the semantic JSON is the same. Canonical META makes the META hash stable, which makes signatures stable.

Editing META

When you modify META, existing signatures become invalid because the section hashes change.

Recommended workflow

1. Modify META while stripping the old signature

    odi meta set ... --strip-signature

2. Re sign the resulting file

    odi sign ... --identity ... --allowed-signers ...
