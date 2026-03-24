# MessageAuthentication

## Intent

`MessageAuthentication` is split into two layers:

- External policy surface:
  `generateMessageAuthenticationKey` and `deriveMessageAuthenticationKey`
- Backwards-compatible runtime surface:
  `.core`

The external policy surface may move to a newer recommended symmetric
authentication algorithm later.

The `.core` surface must stay backwards compatible so old keys keep working
after the default algorithm changes.

## Current default

Current default generation targets `HS256` / `HMAC-SHA-256`.

Current default derivation targets `HKDF-SHA-256` to `HMAC-SHA-256`.

## Responsibilities

### `.core`

`.core` owns algorithm-specific runtime compatibility:

- key validation by `alg` code
- WebCrypto parameter construction by `alg` code
- key import behavior
- sign/verify behavior for every supported historical key algorithm

If a key was ever emitted by this package, `.core` should keep being able to
load and use it.

### External wrappers

`generateMessageAuthenticationKey` and `deriveMessageAuthenticationKey` are
allowed to switch to a newer default algorithm when the recommended standard
changes.

That change must not break old keys, because old keys are handled by `.core`.

### `MessageAuthenticationCluster`

`MessageAuthenticationCluster` should stay mostly algorithm-agnostic. It should
only route keys/messages to the harness and should not become the place where
algorithm branches accumulate.

## Upgrade rule

When upgrading the default algorithm:

1. Add the new key/message types to `.core/types`.
2. Add validation support for the new `alg` in
   `.core/helpers/validateKeyByAlgCode`.
3. Add parameter handling in `.core/helpers/createParamsByAlgCode`,
   `.core/helpers/getParamsByAlgCode`, and
   `.core/helpers/createImportKeyAlgorithmByAlgCode`.
4. Update `.core/MessageAuthenticationKeyHarness` so it can import and use both
   old and new algorithms.
5. Switch `generateMessageAuthenticationKey` and
   `deriveMessageAuthenticationKey` to emit the new default.
6. Keep tests for old algorithms and add tests for the new one.

## Naming rule

Inside `.core`, use standard WebCrypto algorithm names when dealing with
`CryptoKey.algorithm`, for example `HMAC`.

JWK `alg` values such as `HS256` are the external key identifiers. Do not
confuse them with WebCrypto `algorithm.name`.
