# DigitalSignature

## Intent

`DigitalSignature` is split into two layers:

- External policy surface:
  `generateDigitalSignatureKeypair` and `deriveDigitalSignatureKeypair`
- Backwards-compatible runtime surface:
  `.core`

The external policy surface may move to a newer recommended signature algorithm
later.

The `.core` surface must stay backwards compatible so old keys keep working
after the default algorithm changes.

## Current default

Current default generation and derivation target `Ed25519-ML-DSA-65`.

## Responsibilities

### `.core`

`.core` owns algorithm-specific runtime compatibility:

- key validation by `alg` code
- signature parameter construction by `alg` code
- sign/verify behavior for every supported historical signature algorithm

If a key was ever emitted by this package, `.core` should keep being able to
load and use it.

### External wrappers

`generateDigitalSignatureKeypair` and `deriveDigitalSignatureKeypair` are
allowed to switch to a newer default algorithm when the recommended standard
changes.

That change must not break old keys, because old keys are handled by `.core`.

### `DigitalSignatureCluster`

`DigitalSignatureCluster` should stay mostly algorithm-agnostic. It should only
route keys and signatures to the harness and should not become the place where
algorithm branches accumulate.
