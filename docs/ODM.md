# ODM

ODM (Open Data Model) is the canonical metadata encoding used by ODI as `meta_bin`.

ODM exists to solve one problem:
represent structured metadata as bytes in a way that is deterministic, canonical, and easy to validate.

ODI treats ODM as authoritative metadata when present.

## Types

ODM supports these value types:

- null
- bool
- int (signed)
- uint (unsigned)
- bytes (opaque byte string)
- string (UTF-8)
- array (ordered list)
- map (key/value pairs)

## Encoding model

An ODM document is:

- magic: ASCII `ODM1`
- followed by a single encoded value

Values are encoded as TLV:

- tag: 1 byte
- length: unsigned varint (little-endian 7-bit continuation)
- payload: `length` bytes

Composite payloads:

- array payload: `count` varint + `count` encoded values
- map payload: `count` varint + `count` pairs of (encoded string key, encoded value)

## Canonical rules

An ODM encoding is canonical if:

1. **Map keys are strictly sorted** by bytewise lexicographic order on UTF-8 bytes.
2. **Duplicate keys are forbidden.**
3. **Strings are valid UTF-8.**
4. **Integers are minimal** (shortest varint encoding that preserves value).
5. **No floats** (float values MUST be expressed explicitly as strings or integers).

## Minimal ODI schema

ODI keeps the schema small. Tooling requires these fields inside `meta_bin`:

### Required

- `/odi/id` string
- `/odi/version` int or uint

### Recommended

- `/build` map
- `/source` map

## Determinism guidance

ODM can carry unstable data. To keep ODI deterministic:

- avoid wall clock timestamps unless derived from `SOURCE_DATE_EPOCH`
- avoid random identifiers
- if list ordering is semantically irrelevant, sort it before encoding

