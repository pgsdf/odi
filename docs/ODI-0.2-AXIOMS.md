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




## Chosen encoding

ODI 0.2 uses ODM 1.0 as the canonical binary metadata encoding.

- ODM spec: `ODM_SPEC.md`
- ODI stores ODM bytes in the `meta_bin` section

ODI 0.2 retains ODI 0.1 axioms and strengthens Axiom 4 by replacing JSON canonicalization with ODM canonical encoding rules.
