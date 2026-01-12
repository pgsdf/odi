# ODI signing

ODI supports an optional signature section, `sig`.

The signature is detached in the sense that validation and trust policy are external.
ODI defines how bytes are bound, not who is trusted.

## What is signed

The reference tooling signs a canonical text payload derived from the ODI section hashes.

This ensures a signature remains stable and verifiable across transports, mirrors, and file names.

### ODI SIG V1 payload

The signing payload is a UTFिशत 8 text block with a stable field order.

Header line:

- `ODI-SIG-V1`

Then zero or more lines in this exact order, omitting any section that is not present:

1. `payload <alg> <hex>`
2. `meta <alg> <hex>`
3. `meta_bin <alg> <hex>`
4. `manifest <alg> <hex>`

Where:

- `<alg>` is the hash algorithm name, currently `sha256`
- `<hex>` is lowercase hexadecimal, 64 characters for sha256

Example:

    ODI-SIG-V1
    payload sha256 <64 hex chars>
    meta_bin sha256 <64 hex chars>
    manifest sha256 <64 hex chars>

This binds the signature to the exact bytes of each section.

### Why the signature does not include itself

The signature section is not part of the signing payload.
Including it would create a circular dependency.

## How signing is performed

The current implementation uses OpenSSH `ssh-keygen` signing, producing an `sshsig` formatted signature blob.

- `odi sign` writes the SIG V1 payload to a temporary file
- it runs `ssh-keygen -Y sign` to produce a signature
- it writes that signature blob as the `sig` section in a new ODI file

## Verification

`odi verify` can verify signatures when:

- `--allowed-signers <file>` is provided
- `--identity <principal>` is provided

Verification uses OpenSSH verification via `ssh-keygen -Y verify` and checks that the signature validates against the SIG V1 payload.

ODI verification checks signature structure and cryptographic validity.
It does not decide whether the signer should be trusted beyond the allowed signers policy file.

## Editing metadata and signatures

If you modify META or meta_bin, section hashes change and an existing signature becomes invalid.

Recommended workflow:

1. Modify metadata while stripping the old signature

    odi meta set ... --strip-signature
    odi meta patch ... --strip-signature

2. Re sign the resulting file

    odi sign --in <in.odi> --out <out.odi> --key <sshkey> --identity <principal>

