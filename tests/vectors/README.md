# ODI test vectors

This directory contains small ODI files used for cross implementation testing.

## odi-0.1-basic.odi

Contents:

- payload section bytes: b'PAYLOAD'
- meta section bytes: b'{}'
- manifest section bytes: b'{}'

Layout:

- header size: 56
- section entry size: 96
- section count: 3
- table offset: 56
- table length: 288
- payload offset: 344
- meta offset: 351
- manifest offset: 353

Expected SHA 256 digests:

- payload: ea36e4da4017000028db7794d946b152540d7c68bbdb6c60e999f1dce19a409b
- meta: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
- manifest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a

Expected file size: 355 bytes

Validation notes:

- All reserved fields are zero
- hash_len is 32, hash_alg is sha256
- hash field uses first 32 bytes, remaining bytes are zero

## Failing vectors

These vectors are intentionally invalid. Each maps to an ODI axiom.

Run:

    odi verify tests/vectors/<file>
    odi validate tests/vectors/<file>

Expected failures:

- odi-fail-axiom2-bad-magic.odi
  - Axiom 2, section authority, header magic mismatch

- odi-fail-axiom2-overlap.odi
  - Axiom 2, section authority, overlapping sections

- odi-fail-axiom3-hash-mismatch.odi
  - Axiom 3, independent verification, section hash mismatch

- odi-fail-axiom4-meta-not-canonical.odi
  - Axiom 4, canonical metadata, META bytes not canonical

- odi-fail-axiom6-empty-sig.odi
  - Axiom 6, policy exclusion, signature structure invalid



## ODM vectors

These vectors exercise ODM canonical metadata stored in an ODI `meta_bin` section.

- odi-odm-valid.odi
  - valid ODM metadata, should pass verify and validate

- odi-fail-odm-key-order.odi
  - invalid ODM map ordering, should fail canonical validation

- odi-fail-odm-noncanonical-varint.odi
  - invalid ODM varint encoding, should fail canonical validation


## Signature structure vectors

These vectors validate signature section structural rules enforced by `odi validate`:

- odi-sig-utf8-valid.odi
  - signature section exists and is valid UTF-8, should pass validation

- odi-fail-sig-nonutf8.odi
  - signature section exists but contains invalid UTF-8, should fail validation


## Structural negative vectors

These vectors exercise container-level structural invariants.

- odi-fail-overlap-sections.odi
  - section offsets overlap, should fail structure validation

- odi-fail-section-oob.odi
  - section offset points outside file size, should fail structure validation

- odi-fail-invalid-hash-len.odi
  - hash_len not equal to 32 for sha256, should fail structure validation


## Manifest schema negative vectors

These vectors exercise strict manifest schema validation.

- odi-fail-manifest-missing-kind.odi
- odi-fail-manifest-bad-sha256.odi
- odi-fail-manifest-symlink-no-target.odi


## Signature armor vectors

These vectors validate the structural grammar of the `sig` section (OpenSSH sshsig ASCII armor).

- odi-fail-sig-armor-begin.odi
- odi-fail-sig-armor-bad-b64.odi
- odi-fail-sig-armor-missing-end.odi
