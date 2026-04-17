[![npm version](https://img.shields.io/npm/v/@sovereignbase/cryptosuite)](https://www.npmjs.com/package/@sovereignbase/cryptosuite)
[![CI](https://github.com/sovereignbase/cryptosuite/actions/workflows/ci.yaml/badge.svg?branch=master)](https://github.com/sovereignbase/cryptosuite/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/sovereignbase/cryptosuite/branch/master/graph/badge.svg)](https://codecov.io/gh/sovereignbase/cryptosuite)
[![license](https://img.shields.io/npm/l/@sovereignbase/cryptosuite)](LICENSE)

# cryptosuite

JS/TS runtime-agnostic, quantum-safe, and agile cryptography toolkit with a declarative API for cipher messaging, message authentication, digital signatures, key agreement, and identifiers.

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
- Key agreement: `X25519-ML-KEM-768`
- Digital signatures: `Ed25519-ML-DSA-65`

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

const sourceKeyMaterial = Bytes.fromString('k'.repeat(32)) // Uint8Array, exactly 32 bytes

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

const sourceKeyMaterial = Bytes.fromString('s'.repeat(64)) // Uint8Array, exactly 64 bytes
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
- key agreement and digital signatures use `noble` hybrid primitives
- unsupported crypto primitives throw typed `CryptosuiteError` codes

## Security notes

- `AES-CTR` does not provide integrity on its own
- authenticate or sign ciphertexts at the protocol layer
- never reuse a `(key, iv)` pair
- treat JWKs and derived key material as secrets
- sign a canonical byte representation, not loosely structured objects

## Tests

Latest local `npm run test` run on `2026-04-17` with Node `v22.14.0 (win32 x64)`:

- `63/63` tests passed
- Coverage passed at `100%` for statements, branches, functions, and lines
- End-to-end runtime suites all passed in:
  - Node ESM
  - Node CJS
  - Bun ESM
  - Bun CJS
  - Deno ESM
  - Edge Runtime ESM
  - Cloudflare Workers ESM
  - Chromium
  - Firefox
  - WebKit
  - Mobile Chrome emulation
  - Mobile Safari emulation
- The runtime suite currently exercises `20/20` public API scenarios per runtime:
  - 1 static wiring check
  - 19 public methods

## Benchmarks

Latest local `npm run bench` run on `2026-04-17` with Node `v22.14.0 (win32 x64)`.

| Benchmark                           | ops |      ms |   ms/op |   ops/sec |
| ----------------------------------- | --: | ------: | ------: | --------: |
| `identifier.generate`               | 100 |    3.76 |  0.0376 |  26617.69 |
| `identifier.derive`                 | 100 |   32.60 |  0.3260 |   3067.77 |
| `identifier.validate`               | 100 |    0.43 |  0.0043 | 232883.09 |
| `cipherMessage.generateKey`         | 100 |   43.36 |  0.4336 |   2306.01 |
| `cipherMessage.deriveKey`           | 100 |   75.53 |  0.7553 |   1324.01 |
| `cipherMessage.encrypt`             | 100 |   38.18 |  0.3818 |   2619.10 |
| `cipherMessage.decrypt`             | 100 |   30.86 |  0.3086 |   3240.51 |
| `messageAuthentication.generateKey` | 100 |   42.06 |  0.4206 |   2377.45 |
| `messageAuthentication.deriveKey`   | 100 |   67.14 |  0.6714 |   1489.35 |
| `messageAuthentication.sign`        | 100 |   26.91 |  0.2691 |   3716.46 |
| `messageAuthentication.verify`      | 100 |   28.26 |  0.2826 |   3538.58 |
| `keyAgreement.generateKeypair`      | 100 |  877.66 |  8.7766 |    113.94 |
| `keyAgreement.deriveKeypair`        | 100 |  728.01 |  7.2801 |    137.36 |
| `keyAgreement.encapsulate`          | 100 | 1649.16 | 16.4916 |     60.64 |
| `keyAgreement.decapsulate`          | 100 | 1093.07 | 10.9307 |     91.49 |
| `digitalSignature.generateKeypair`  | 100 |  849.80 |  8.4980 |    117.67 |
| `digitalSignature.deriveKeypair`    | 100 |  714.64 |  7.1464 |    139.93 |
| `digitalSignature.sign`             | 100 | 3293.13 | 32.9313 |     30.37 |
| `digitalSignature.verify`           | 100 | 1195.09 | 11.9509 |     83.68 |

Results vary by machine and Node version.

## Credits

Post-quantum primitives are built on top of [noble](https://paulmillr.com/noble/).

Thanks to Paul Miller for an unusually clear, well-engineered, and genuinely awesome project.

## License

Apache-2.0
