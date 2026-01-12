# ODI META

The META section holds structured metadata for an ODI file.

META is JSON

The META payload is a single UTF 8 JSON document.

Pointer addressing

The reference implementation uses JSON Pointer (RFC 6901) to read and write nested fields.

Canonicalization

ODI requires META to be canonicalized before it is written.

Rules

1. UTF 8 encoding
2. Minified JSON with no insignificant whitespace
3. Object keys sorted lexicographically at every object level
4. Array order preserved
5. Standard JSON string escaping for quotes, backslash, and control characters
6. Deterministic number formatting
7. No trailing newline

CLI examples

Read a value

    odi meta get image.odi /odi/version

Set a JSON value

    odi meta set image.odi /odi/version \"1.2.3\" --out image2.odi --json-value

Set a string value, even if it looks like JSON

    odi meta set image.odi /note '{not json}' --out image2.odi --string
