# ODI 0.2 axioms sketch

This document is non normative. It sketches axioms for a possible ODI 0.2 that replaces META JSON with a canonical binary metadata encoding.

The goal is to keep ODI truths stable, while making metadata even more mechanically enforceable.

## Axiom set

ODI 0.2 keeps ODI 0.1 axioms and adds the following.

### Axiom 8: Typed metadata

Metadata values have explicit types and a single canonical encoding.
There is no ambiguous number spelling, no stringly typed booleans, and no undefined null semantics.

### Axiom 9: Schema anchored metadata

Metadata fields are defined by the specification.
Unknown fields are either explicitly allowed by extension points, or are rejected.
The format does not rely on ad hoc conventions.

### Axiom 10: Canonical binary encoding

The META encoding is binary and canonical.
The same semantic metadata produces identical bytes across implementations.

Possible encodings:

- Canonical CBOR with fixed rules
- A minimal ODI TLV encoding with sorted keys and stable varints

## Compatibility strategy

ODI 0.2 should preserve:

- section hashing model
- section authority
- independent verification
- policy exclusion
- artifact identity

ODI 0.2 changes:

- META section payload format
- META canonicalization rules

A migration path can be:

- Allow both meta json and meta bin sections during a transition period
- Require exactly one meta section in the final 0.2 contract

End of document.
