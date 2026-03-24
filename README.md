[![npm version](https://img.shields.io/npm/v/@sovereignbase/cryptosuite)](https://www.npmjs.com/package/@sovereignbase/cryptosuite)
[![CI](https://github.com/sovereignbase/cryptosuite/actions/workflows/ci.yaml/badge.svg?branch=master)](https://github.com/sovereignbase/cryptosuite/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/sovereignbase/cryptosuite/branch/master/graph/badge.svg)](https://codecov.io/gh/sovereignbase/cryptosuite)
[![license](https://img.shields.io/npm/l/@sovereignbase/cryptosuite)](LICENSE)

# cryptosuite

JS/TS runtime-agnostic, post-quantum, crypto-agile cryptography toolkit with a declarative API for cipher messaging, message authentication, digital signatures, key agreement, and identifiers.

## Compatibility

- Runtimes: Tested on browsers, bun, deno, node, edge-runtimes.
- Module format: ESM or CJS
- Required globals / APIs: `crypto`, `crypto.subtle`, `crypto.getRandomValues`
- Types: bundled `.d.ts`

## Goals

- Runtime-agnostic across modern JavaScript and TypeScript environments
- Post-quantum by default
- Crypto-agile, with room to add or replace algorithms as recommendations evolve while keeping already issued keys backwards compatible
- Declarative API surface that expresses cryptographic intent clearly

## Current algorithms

- Identifier: `SHA-384` or 48 random bytes, encoded as a fixed-length base64url string
- Cipher messaging: `AES-CTR-256`
- Message authentication: `HMAC-SHA-256`
- Key agreement: `ML-KEM-1024`
- Digital signatures: `ML-DSA-87`

## Installation

```sh
npm install @sovereignbase/cryptosuite
# or
pnpm add @sovereignbase/cryptosuite
# or
yarn add @sovereignbase/cryptosuite
# or
bun add @sovereignbase/cryptosuite
# or
deno add jsr:@sovereignbase/cryptosuite
# or
vlt install jsr:@sovereignbase/cryptosuite
```

## Usage

### Identifiers

```ts
import { Cryptographic } from '@sovereignbase/cryptosuite'
import { Bytes } from '@sovereignbase/bytecodec'

const discoveryHook = Bytes.fromString('resource discovery hook') // Uint8Array

const newResourceId = await Cryptographic.identifier.generate() // "64xb64urlchars..."
const discoveryId = await Cryptographic.identifier.derive(discoveryHook) // "64xb64urlchars..."
const ingressId = Cryptographic.identifier.validate(discoveryId) // "64xb64urlchars..." | false
```

### Cipher messages

```ts
import { Cryptographic } from '@sovereignbase/cryptosuite'
import { Bytes } from '@sovereignbase/bytecodec'

const messageBytes = Bytes.fromString('hello world') // Uint8Array

const cipherKey = await Cryptographic.cipherMessage.generateKey() // JsonWebKey

const sourceKeyMaterial = Bytes.fromString('deterministic key source') // Uint8Array
const salt = Bytes.fromString('deterministic salt source') // Uint8Array
const { cipherKey } = await Cryptographic.cipherMessage.deriveKey(
  sourceKeyMaterial,
  { salt }
) // {cipherKey: JsonWebKey, salt: Uint8Array}

const cipherMessage = await Cryptographic.cipherMessage.encrypt(
  cipherKey,
  messageBytes
) // {ciphertext: ArrayBuffer, iv: Uint8Array}
const roundtrip = await Cryptographic.cipherMessage.decrypt(
  cipherKey,
  cipherMessage
) // Uint8Array

const plainMessage = Bytes.toString(roundtrip) // 'hello world'
```

### Message authentication

```ts
import { Cryptographic } from '@sovereignbase/cryptosuite'
import { Bytes } from '@sovereignbase/bytecodec'

const messageBytes = Bytes.fromString('authenticated payload') // Uint8Array

const generatedMessageAuthenticationKey =
  await Cryptographic.messageAuthentication.generateKey() // JsonWebKey

const sourceKeyMaterial = Bytes.fromString('deterministic key source') // Uint8Array
const salt = Bytes.fromString('deterministic salt source') // Uint8Array

const { messageAuthenticationKey } =
  await Cryptographic.messageAuthentication.deriveKey(sourceKeyMaterial, {
    salt,
  }) // {messageAuthenticationKey: JsonWebKey, salt: Uint8Array}

const tag = await Cryptographic.messageAuthentication.sign(
  generatedMessageAuthenticationKey,
  messageBytes
) // ArrayBuffer

const verified = await Cryptographic.messageAuthentication.verify(
  generatedMessageAuthenticationKey,
  messageBytes,
  tag
) // boolean
```

### Key agreement

```ts
import { Cryptographic } from '@sovereignbase/cryptosuite'
import { Bytes } from '@sovereignbase/bytecodec'

const sourceKeyMaterial = Bytes.fromString('k'.repeat(64)) // Uint8Array, exactly 64 bytes

const { encapsulateKey, decapsulateKey } =
  await Cryptographic.keyAgreement.generateKeypair() // {encapsulateKey: JsonWebKey, decapsulateKey: JsonWebKey}

const deterministicKeypair =
  await Cryptographic.keyAgreement.deriveKeypair(sourceKeyMaterial) // {encapsulateKey: JsonWebKey, decapsulateKey: JsonWebKey}

const { keyOffer, cipherKey: senderCipherKey } =
  await Cryptographic.keyAgreement.encapsulate(encapsulateKey) // {keyOffer: {ciphertext: ArrayBuffer}, cipherKey: JsonWebKey}

const { cipherKey: receiverCipherKey } =
  await Cryptographic.keyAgreement.decapsulate(keyOffer, decapsulateKey) // {cipherKey: JsonWebKey}
```

### Digital signatures

```ts
import { Cryptographic } from '@sovereignbase/cryptosuite'
import { Bytes } from '@sovereignbase/bytecodec'

const sourceKeyMaterial = Bytes.fromString('s'.repeat(32)) // Uint8Array, exactly 32 bytes
const bytes = Bytes.fromString('signed payload') // Uint8Array
const { signKey, verifyKey } =
  await Cryptographic.digitalSignature.generateKeypair() // {signKey: JsonWebKey, verifyKey: JsonWebKey}

const deterministicKeypair =
  await Cryptographic.digitalSignature.deriveKeypair(sourceKeyMaterial) // {signKey: JsonWebKey, verifyKey: JsonWebKey}

const signature = await Cryptographic.digitalSignature.sign(signKey, bytes) // Uint8Array
const verified = await Cryptographic.digitalSignature.verify(
  verifyKey,
  bytes,
  signature
) // boolean
```

## Runtime behavior

- `identifier.generate()` requires `crypto.getRandomValues`
- symmetric operations use WebCrypto
- key agreement and digital signatures use `@noble/post-quantum`
- unsupported crypto primitives throw typed `CryptosuiteError` codes

## Security notes

- `AES-CTR` does not provide integrity on its own
- authenticate or sign ciphertexts at the protocol layer
- never reuse a `(key, iv)` pair
- treat JWKs and derived key material as secrets
- sign a canonical byte representation, not loosely structured objects

## Tests

- Unit + integration tests run against the built artifact
- Coverage targets `dist/index.cjs` and is enforced at `100%`
- E2E runtime suites currently run in:
  - Node ESM
  - Node CJS
  - Bun ESM
  - Bun CJS
  - Deno ESM
  - Edge Runtime ESM
  - Chromium
  - Firefox
  - WebKit
  - Mobile Chrome emulation
  - Mobile Safari emulation
- The runtime suite currently exercises `20/20` public API scenarios per runtime:
  - 1 static wiring check
  - 19 public methods

## Benchmarks

Latest local `npm run bench` run on 2026-03-24 with Node `v22.14.0 (win32 x64)`:

| Benchmark                           | Result                      |
| ----------------------------------- | --------------------------- |
| `identifier.generate`               | `3.50ms (57206.6 ops/sec)`  |
| `identifier.derive`                 | `13.94ms (14349.8 ops/sec)` |
| `identifier.validate`               | `0.33ms (609942.1 ops/sec)` |
| `cipherMessage.generateKey`         | `23.03ms (8682.6 ops/sec)`  |
| `cipherMessage.deriveKey`           | `49.73ms (4021.6 ops/sec)`  |
| `cipherMessage.encrypt`             | `20.91ms (9566.5 ops/sec)`  |
| `cipherMessage.decrypt`             | `19.18ms (10425.0 ops/sec)` |
| `messageAuthentication.generateKey` | `24.58ms (8135.2 ops/sec)`  |
| `messageAuthentication.deriveKey`   | `12.51ms (15987.5 ops/sec)` |
| `messageAuthentication.sign`        | `12.94ms (15460.4 ops/sec)` |
| `messageAuthentication.verify`      | `14.96ms (13365.2 ops/sec)` |
| `keyAgreement.generateKeypair`      | `43.89ms (455.7 ops/sec)`   |
| `keyAgreement.deriveKeypair`        | `35.21ms (568.1 ops/sec)`   |
| `keyAgreement.encapsulate`          | `43.76ms (457.0 ops/sec)`   |
| `keyAgreement.decapsulate`          | `45.16ms (442.9 ops/sec)`   |
| `digitalSignature.generateKeypair`  | `165.49ms (120.8 ops/sec)`  |
| `digitalSignature.deriveKeypair`    | `153.20ms (130.6 ops/sec)`  |
| `digitalSignature.sign`             | `431.41ms (46.4 ops/sec)`   |
| `digitalSignature.verify`           | `155.20ms (128.9 ops/sec)`  |

Command: `npm run bench`

Results vary by machine and Node version.

## Credits

Post-quantum primitives are built on top of [noble](https://paulmillr.com/noble/).

Thanks to Paul Miller for an unusually clear, well-engineered, and genuinely awesome project.

## License

Apache-2.0
