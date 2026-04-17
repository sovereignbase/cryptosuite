# KeyAgreement

## Intent

`KeyAgreement` is split into two layers:

- External policy surface:
  `generateKeyAgreementKeypair` and `deriveKeyAgreementKeypair`
- Backwards-compatible runtime surface:
  `.core`

The external policy surface may move to a newer recommended key agreement
algorithm later.

The `.core` surface must stay backwards compatible so old keys keep working
after the default algorithm changes.

## Current default

Current default generation and derivation target `X25519-ML-KEM-768`.

Encapsulation returns a `KeyOffer` and a symmetric `CipherKey`.

Decapsulation takes that `KeyOffer` and reconstructs the same `CipherKey`.

The shared secret is used directly as raw `AES-GCM-256` key material and is
then normalized through `CipherMessage` key validation.

## Responsibilities

### `.core`

`.core` owns algorithm-specific runtime compatibility:

- key validation by `alg` code
- key agreement parameter construction by `alg` code
- encapsulate/decapsulate behavior for every supported historical key
  agreement algorithm

If a key was ever emitted by this package, `.core` should keep being able to
load and use it.

### External wrappers

`generateKeyAgreementKeypair` and `deriveKeyAgreementKeypair` are allowed to
switch to a newer default algorithm when the recommended standard changes.

That change must not break old keys, because old keys are handled by `.core`.

### `KeyAgreementCluster`

`KeyAgreementCluster` should stay mostly algorithm-agnostic. It should only
route keys and key offers to the harness and should not become the place where
algorithm branches accumulate.

## Upgrade rule

When upgrading the default algorithm:

1. Add the new key and key-offer types to `.core/types`.
2. Add validation support for the new `alg` in
   `.core/helpers/validateKeyByAlgCode`.
3. Add parameter handling in `.core/helpers/createParamsByAlgCode`,
   `.core/helpers/getParamsByAlgCode`, and
   `.core/helpers/createImportKeyAlgorithmByAlgCode`.
4. Update `.core/EncapsulateKeyHarness` and `.core/DecapsulateKeyHarness` so
   they can use both old and new algorithms.
5. Switch `generateKeyAgreementKeypair` and `deriveKeyAgreementKeypair` to
   emit the new default.
6. Keep tests for old algorithms and add tests for the new one.

## Naming rule

Inside `.core`, JWK `alg` values such as `ML-KEM-1024` or
`X25519-ML-KEM-768` are the external key
identifiers and the routing source of truth.

Do not add extra algorithm-name translation layers unless the runtime actually
requires one.
