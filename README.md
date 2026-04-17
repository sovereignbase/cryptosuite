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
- Cipher messaging: `AES-GCM-256`
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

- `AES-GCM` provides confidentiality and message integrity for each ciphertext
- authenticate peers and session setup at the protocol layer
- never reuse a `(key, iv)` pair
- treat JWKs and derived key material as secrets
- sign a canonical byte representation, not loosely structured objects

## Tests

Latest local `npm run test` run on `2026-04-17` with Node `v22.14.0 (win32 x64)`:

- `65/65` tests passed
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
| `identifier.generate`               | 100 |    2.91 |  0.0291 |  34389.08 |
| `identifier.derive`                 | 100 |   34.97 |  0.3497 |   2859.53 |
| `identifier.validate`               | 100 |    0.41 |  0.0041 | 243961.94 |
| `cipherMessage.generateKey`         | 100 |   48.77 |  0.4877 |   2050.38 |
| `cipherMessage.deriveKey`           | 100 |   67.84 |  0.6784 |   1474.02 |
| `cipherMessage.encrypt`             | 100 |   36.80 |  0.3680 |   2717.03 |
| `cipherMessage.decrypt`             | 100 |   36.02 |  0.3602 |   2776.57 |
| `messageAuthentication.generateKey` | 100 |   44.84 |  0.4484 |   2230.24 |
| `messageAuthentication.deriveKey`   | 100 |   75.64 |  0.7564 |   1322.07 |
| `messageAuthentication.sign`        | 100 |   29.09 |  0.2909 |   3437.31 |
| `messageAuthentication.verify`      | 100 |   25.33 |  0.2533 |   3947.69 |
| `keyAgreement.generateKeypair`      | 100 |  827.02 |  8.2702 |    120.92 |
| `keyAgreement.deriveKeypair`        | 100 |  842.11 |  8.4211 |    118.75 |
| `keyAgreement.encapsulate`          | 100 | 1669.17 | 16.6917 |     59.91 |
| `keyAgreement.decapsulate`          | 100 | 1240.95 | 12.4095 |     80.58 |
| `digitalSignature.generateKeypair`  | 100 |  808.57 |  8.0857 |    123.67 |
| `digitalSignature.deriveKeypair`    | 100 |  612.56 |  6.1256 |    163.25 |
| `digitalSignature.sign`             | 100 | 3478.93 | 34.7893 |     28.74 |
| `digitalSignature.verify`           | 100 | 2574.33 | 25.7433 |     38.85 |

Results vary by machine and Node version.

## Credits

Post-quantum primitives are built on top of [noble](https://paulmillr.com/noble/).

Thanks to Paul Miller for an unusually clear, well-engineered, and genuinely awesome project.

## License

Apache-2.0
