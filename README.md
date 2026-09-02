[![npm version](https://img.shields.io/npm/v/@sovereignbase/cryptosuite)](https://www.npmjs.com/package/@sovereignbase/cryptosuite)
[![JSR](https://jsr.io/badges/@sovereignbase/cryptosuite)](https://jsr.io/@sovereignbase/cryptosuite)
[![CI](https://github.com/sovereignbase/cryptosuite/actions/workflows/ci.yaml/badge.svg?branch=master)](https://github.com/sovereignbase/cryptosuite/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/sovereignbase/cryptosuite/branch/master/graph/badge.svg)](https://codecov.io/gh/sovereignbase/cryptosuite)
[![license](https://img.shields.io/npm/l/@sovereignbase/cryptosuite)](LICENSE)

# cryptosuite

JS/TS runtime-agnostic, quantum-safe, and agile cryptography toolkit with a
declarative API for opaque identifiers, cipher messaging, message
authentication, digital signatures, and key agreement.

## Compatibility

- Runtimes: Tested on browsers, Bun, Cloudflare Workers, Deno, Edge Runtime,
  and Node.js.
- Module format: ESM or CJS
- Required globals / APIs: `crypto`, `crypto.subtle`, `crypto.getRandomValues`
- Types: bundled `.d.ts`

## Goals

- Runtime-agnostic across modern JavaScript and TypeScript environments
- Post-quantum by default
- Crypto-agile, with room to add or replace algorithms as recommendations evolve while keeping already issued keys backwards compatible
- Declarative API surface that expresses cryptographic intent clearly

## Current algorithms

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

The package root exposes the complete declarative API through `Cryptographic`.
Each cryptographic area also has a focused entry point:

```ts
import { Cryptographic } from '@sovereignbase/cryptosuite'
import { CipherCluster } from '@sovereignbase/cryptosuite/CipherMessage'
import { DigitalSignatureCluster } from '@sovereignbase/cryptosuite/DigitalSignature'
import { Identifier } from '@sovereignbase/cryptosuite/Identifier'
import { KeyAgreementCluster } from '@sovereignbase/cryptosuite/KeyAgreement'
import { MessageAuthenticationCluster } from '@sovereignbase/cryptosuite/MessageAuthentication'
```

### Identifiers

```ts
import { Cryptographic } from '@sovereignbase/cryptosuite'

const randomId = Cryptographic.identifier.generate(32)
const valid = Cryptographic.identifier.validate(randomId, 32) // true

const accountId = await Cryptographic.identifier.derive(
  { value: 'tenant-123' },
  { value: 'account-id' },
  32
)
```

Generated and derived identifiers are canonical, unpadded base64url strings.
Derivation is deterministic for the same base, domain, and byte length. Use a
distinct domain for every identifier purpose.

### Cipher messages

```ts
import { Cryptographic } from '@sovereignbase/cryptosuite'
import { Bytes } from '@sovereignbase/bytecodec'

const messageBytes = Bytes.utf8.decode('hello world') // Uint8Array

const cipherKey = await Cryptographic.cipherMessage.generateKey() // JsonWebKey

const sourceKeyMaterial = Bytes.utf8.decode('deterministic key source') // Uint8Array
const salt = Bytes.utf8.decode('deterministic salt source') // Uint8Array
const cipherKey = await Cryptographic.cipherMessage.deriveKey(
  sourceKeyMaterial,
  salt
) // JsonWebKey

const cipherMessage = await Cryptographic.cipherMessage.encrypt(
  cipherKey,
  messageBytes
) // {ciphertext: Uint8Array, iv: Uint8Array}
const roundtrip = await Cryptographic.cipherMessage.decrypt(
  cipherKey,
  cipherMessage
) // Uint8Array

const plainMessage = Bytes.utf8.encode(roundtrip) // 'hello world'
```

### Message authentication

```ts
import { Cryptographic } from '@sovereignbase/cryptosuite'
import { Bytes } from '@sovereignbase/bytecodec'

const messageBytes = Bytes.utf8.decode('authenticated payload') // Uint8Array

const generatedMessageAuthenticationKey =
  await Cryptographic.messageAuthentication.generateKey() // JsonWebKey

const sourceKeyMaterial = Bytes.utf8.decode('deterministic key source') // Uint8Array
const salt = Bytes.utf8.decode('deterministic salt source') // Uint8Array

const messageAuthenticationKey =
  await Cryptographic.messageAuthentication.deriveKey(sourceKeyMaterial, salt) // JsonWebKey

const tag = await Cryptographic.messageAuthentication.sign(
  generatedMessageAuthenticationKey,
  messageBytes
) // Uint8Array

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

const sourceKeyMaterial = Bytes.utf8.decode('k'.repeat(32)) // Uint8Array, exactly 32 bytes

const { encapsulateKey, decapsulateKey } =
  await Cryptographic.keyAgreement.generateKeypair() // {encapsulateKey: JsonWebKey, decapsulateKey: JsonWebKey}

const deterministicKeypair =
  await Cryptographic.keyAgreement.deriveKeypair(sourceKeyMaterial) // {encapsulateKey: JsonWebKey, decapsulateKey: JsonWebKey}

const { keyOffer, cipherKey: senderCipherKey } =
  await Cryptographic.keyAgreement.encapsulate(encapsulateKey) // {keyOffer: {ciphertext: Uint8Array}, cipherKey: JsonWebKey}

const { cipherKey: receiverCipherKey } =
  await Cryptographic.keyAgreement.decapsulate(keyOffer, decapsulateKey) // {cipherKey: JsonWebKey}
```

### Digital signatures

```ts
import { Cryptographic } from '@sovereignbase/cryptosuite'
import { Bytes } from '@sovereignbase/bytecodec'

const sourceKeyMaterial = Bytes.utf8.decode('s'.repeat(64)) // Uint8Array, exactly 64 bytes
const bytes = Bytes.utf8.decode('signed payload') // Uint8Array
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

- symmetric operations use WebCrypto
- symmetric key derivation accepts an optional salt and always uses a
  key-type-specific HKDF `info` value for domain separation
- key agreement and digital signatures use `noble` hybrid primitives
- all byte inputs and outputs are normalized to `Uint8Array`
- unsupported crypto primitives throw typed `CryptosuiteError` codes

## Security notes

- `AES-GCM` provides confidentiality and message integrity for each ciphertext
- authenticate peers and session setup at the protocol layer
- never reuse a `(key, iv)` pair
- treat JWKs and derived key material as secrets
- sign a canonical byte representation, not loosely structured objects

## Tests

Latest local `npm test` run on `2026-09-02` with Node `v24.16.0 (win32 x64)`:

- `73/73` unit and integration tests passed
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
  - Mobile Chromium emulation
  - Mobile Firefox emulation
  - Mobile WebKit emulation
- The runtime suite currently exercises `20/20` public API scenarios per runtime:
  - 1 static wiring check
  - 19 public methods

## Benchmarks

Latest local `npm run bench` run on `2026-08-29` with Node `v24.16.0 (win32 x64)`.

| Benchmark                           | ops |      ms |   ms/op |  ops/sec |
| ----------------------------------- | --: | ------: | ------: | -------: |
| `cipherMessage.generateKey`         | 100 |   17.36 |  0.1736 |  5759.77 |
| `cipherMessage.deriveKey`           | 100 |   41.96 |  0.4196 |  2383.23 |
| `cipherMessage.encrypt`             | 100 |   18.99 |  0.1899 |  5264.71 |
| `cipherMessage.decrypt`             | 100 |   18.93 |  0.1893 |  5282.15 |
| `messageAuthentication.generateKey` | 100 |   18.20 |  0.1820 |  5494.17 |
| `messageAuthentication.deriveKey`   | 100 |   38.44 |  0.3844 |  2601.46 |
| `messageAuthentication.sign`        | 100 |    8.57 |  0.0857 | 11672.70 |
| `messageAuthentication.verify`      | 100 |    7.58 |  0.0758 | 13199.93 |
| `keyAgreement.generateKeypair`      | 100 |  312.30 |  3.1230 |   320.20 |
| `keyAgreement.deriveKeypair`        | 100 |  244.60 |  2.4460 |   408.84 |
| `keyAgreement.encapsulate`          | 100 |  990.29 |  9.9029 |   100.98 |
| `keyAgreement.decapsulate`          | 100 |  803.80 |  8.0380 |   124.41 |
| `digitalSignature.generateKeypair`  | 100 |  500.13 |  5.0013 |   199.95 |
| `digitalSignature.deriveKeypair`    | 100 |  384.87 |  3.8487 |   259.83 |
| `digitalSignature.sign`             | 100 | 1922.69 | 19.2269 |    52.01 |
| `digitalSignature.verify`           | 100 |  626.36 |  6.2636 |   159.65 |

Results vary by machine and Node version.

## Credits

Post-quantum primitives are built on top of [noble](https://paulmillr.com/noble/).

Thanks to Paul Miller for an unusually clear, well-engineered, and genuinely awesome project.

## License

Apache-2.0
