# Commands

## Manifest dump

- `odi manifest dump <file.odi> [--json]`

## Manifest diff

- `odi manifest diff [--json] [--content-only] [--limit N] [--fail-fast] <a.odi> <b.odi>`

## Manifest hash

- `odi manifest hash <file.odi> [--json]`

## Attest

- `odi manifest attest <file.odi> [--json] [--verify]`

## Sign

- `odi sign <in.odi> --out <signed.odi> --key <private_key> --identity <principal>`

## Verify

- `odi verify [--verify-hashes] [--require-manifest] [--require-signature --allowed-signers <file> --identity <principal>] <file.odi>`

## Meta

- `odi meta get <file.odi> <json-pointer> [--json]`
- `odi meta set <file.odi> <json-pointer> <value> --out <new.odi> [--strip-signature] [--json-value|--string]`
- `odi meta patch <file.odi> --patch <file.json> --out <new.odi> [--strip-signature]`

## Provenance

- `odi manifest provenance <file.odi> [--json] [--verify]`

## Check tree

- `odi manifest check-tree <root-dir> <file.odi> [--json] [--content-only] [--limit N] [--fail-fast]`

## Test vectors

ODI test vectors live in `tests/vectors`. Each vector includes an ODI file plus expected hashes and layout metadata.


Note: CLI `odi meta` operates on effective metadata. If `meta_bin` (ODM) is present, it is preferred; otherwise JSON `meta` is used.


### Strict metadata mode

- `odi validate <file.odi> --require-meta-bin`
  - require `meta_bin` (ODM) to be present

- `odi verify <file.odi> --require-meta-bin`
  - require `meta_bin` (ODM) to be present
