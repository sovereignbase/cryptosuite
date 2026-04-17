import assert from 'node:assert/strict'
import test from 'node:test'
import { webcrypto } from 'node:crypto'
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { createImportKeyAlgorithmByAlgCode } from '../../src/KeyAgreement/.core/helpers/createImportKeyAlgorithmByAlgCode/index.ts'
import { createParamsByAlgCode } from '../../src/KeyAgreement/.core/helpers/createParamsByAlgCode/index.ts'
import { getParamsByAlgCode } from '../../src/KeyAgreement/.core/helpers/getParamsByAlgCode/index.ts'
import { validateKeyByAlgCode } from '../../src/KeyAgreement/.core/helpers/validateKeyByAlgCode/index.ts'
import { DecapsulateKeyHarness } from '../../src/KeyAgreement/.core/DecapsulateKeyHarness/class.ts'
import { EncapsulateKeyHarness } from '../../src/KeyAgreement/.core/EncapsulateKeyHarness/class.ts'
import {
  buildCrypto,
  expectCodeAsync,
  expectCodeSync,
  restoreCrypto,
  setCrypto,
} from '../support/index.mjs'
import {
  createA256CtrKey,
  createMlKemPrivateKey,
  createMlKemPublicKey,
  createX25519MlKem768PrivateKey,
  createX25519MlKem768PublicKey,
  filledBytes,
} from '../support/fixtures.mjs'

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto
}

test.afterEach(() => {
  restoreCrypto()
})

test('source key agreement helpers cover validation and unsupported branches', () => {
  expectCodeSync(() => validateKeyByAlgCode(null), 'KEY_AGREEMENT_KEY_INVALID')
  expectCodeSync(
    () => validateKeyByAlgCode(createMlKemPublicKey({ kty: 'oct' })),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createMlKemPublicKey({ use: 'sig' })),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createMlKemPrivateKey({ key_ops: ['encrypt'] })),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createMlKemPrivateKey({ d: 'A' })),
    'BASE64URL_INVALID'
  )
  expectCodeSync(
    () =>
      validateKeyByAlgCode(
        createMlKemPrivateKey({
          d: Buffer.from([1]).toString('base64url'),
        })
      ),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () =>
      validateKeyByAlgCode(createMlKemPublicKey({ key_ops: ['deriveKey'] })),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createMlKemPublicKey({ x: 'A' })),
    'BASE64URL_INVALID'
  )
  expectCodeSync(
    () =>
      validateKeyByAlgCode(
        createMlKemPublicKey({
          x: Buffer.from([1]).toString('base64url'),
        })
      ),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode({ kty: 'AKP', alg: 'ML-KEM-1024' }),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createMlKemPublicKey({ alg: 'ML-KEM-768' })),
    'ALGORITHM_UNSUPPORTED'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createX25519MlKem768PublicKey({ kty: 'oct' })),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () =>
      validateKeyByAlgCode(
        createX25519MlKem768PrivateKey({
          d: Buffer.from([1]).toString('base64url'),
        })
      ),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () =>
      validateKeyByAlgCode(
        createX25519MlKem768PublicKey({
          x: Buffer.from([1]).toString('base64url'),
        })
      ),
    'KEY_AGREEMENT_KEY_INVALID'
  )

  const normalizedPrivate = validateKeyByAlgCode(
    createMlKemPrivateKey({ key_ops: undefined, extra: 'ok' })
  )
  assert.equal(normalizedPrivate.use, 'enc')
  assert.deepEqual(normalizedPrivate.key_ops, ['deriveKey', 'deriveBits'])
  assert.equal(normalizedPrivate.extra, 'ok')

  const normalizedPublic = validateKeyByAlgCode(
    createMlKemPublicKey({ key_ops: undefined, extra: 'ok' })
  )
  assert.equal(normalizedPublic.use, 'enc')
  assert.deepEqual(normalizedPublic.key_ops, [])
  assert.equal(normalizedPublic.extra, 'ok')

  assert.equal(createImportKeyAlgorithmByAlgCode('ML-KEM-1024'), ml_kem1024)
  assert.equal(
    createImportKeyAlgorithmByAlgCode('X25519-ML-KEM-768'),
    ml_kem768_x25519
  )
  expectCodeSync(
    () => createImportKeyAlgorithmByAlgCode('ML-KEM-768'),
    'ALGORITHM_UNSUPPORTED'
  )

  const publicParams = createParamsByAlgCode(createMlKemPublicKey())
  assert.equal(publicParams.publicKey.byteLength, ml_kem1024.lengths.publicKey)
  const secretParams = createParamsByAlgCode(createMlKemPrivateKey())
  assert.equal(secretParams.secretKey.byteLength, ml_kem1024.lengths.secretKey)
  expectCodeSync(() => createParamsByAlgCode({}), 'KEY_AGREEMENT_KEY_INVALID')

  assert.equal(getParamsByAlgCode('ML-KEM-1024', publicParams), publicParams)
  expectCodeSync(
    () => getParamsByAlgCode('ML-KEM-768', publicParams),
    'ALGORITHM_UNSUPPORTED'
  )
  const hybridPublicParams = createParamsByAlgCode(
    createX25519MlKem768PublicKey()
  )
  assert.equal(
    hybridPublicParams.publicKey.byteLength,
    ml_kem768_x25519.lengths.publicKey
  )
  const hybridSecretParams = createParamsByAlgCode(
    createX25519MlKem768PrivateKey()
  )
  assert.equal(
    hybridSecretParams.secretKey.byteLength,
    ml_kem768_x25519.lengths.secretKey
  )
  assert.equal(
    getParamsByAlgCode('X25519-ML-KEM-768', hybridPublicParams),
    hybridPublicParams
  )
})

test('source key agreement harnesses cover constructor, invariant, and export branches', async () => {
  setCrypto({})
  expectCodeSync(
    () => new EncapsulateKeyHarness(createMlKemPublicKey()),
    'SUBTLE_UNAVAILABLE'
  )
  expectCodeSync(
    () => new DecapsulateKeyHarness(createMlKemPrivateKey()),
    'SUBTLE_UNAVAILABLE'
  )

  setCrypto(buildCrypto())
  expectCodeSync(
    () => new EncapsulateKeyHarness(createMlKemPrivateKey()),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () => new DecapsulateKeyHarness(createMlKemPublicKey()),
    'KEY_AGREEMENT_KEY_INVALID'
  )

  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => {
          throw new Error('no')
        },
      },
    })
  )
  const encapsulateImportFail = new EncapsulateKeyHarness(
    createMlKemPublicKey()
  )
  await expectCodeAsync(
    () => encapsulateImportFail.exportCipherKey(filledBytes(32, 1)),
    'ALGORITHM_UNSUPPORTED'
  )
  const decapsulateImportFail = new DecapsulateKeyHarness(
    createMlKemPrivateKey()
  )
  await expectCodeAsync(
    () => decapsulateImportFail.exportCipherKey(filledBytes(32, 1)),
    'ALGORITHM_UNSUPPORTED'
  )

  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        exportKey: async () => {
          throw new Error('no')
        },
      },
    })
  )
  const encapsulateExportFail = new EncapsulateKeyHarness(
    createMlKemPublicKey()
  )
  await expectCodeAsync(
    () => encapsulateExportFail.exportCipherKey(filledBytes(32, 1)),
    'EXPORT_FAILED'
  )
  const decapsulateExportFail = new DecapsulateKeyHarness(
    createMlKemPrivateKey()
  )
  await expectCodeAsync(
    () => decapsulateExportFail.exportCipherKey(filledBytes(32, 1)),
    'EXPORT_FAILED'
  )

  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        exportKey: async () => createA256CtrKey({ k: 'A' }),
      },
    })
  )
  const encapsulateReThrowHarness = new EncapsulateKeyHarness(
    createMlKemPublicKey()
  )
  await expectCodeAsync(
    () => encapsulateReThrowHarness.exportCipherKey(filledBytes(32, 1)),
    'BASE64URL_INVALID'
  )
  const decapsulateReThrowHarness = new DecapsulateKeyHarness(
    createMlKemPrivateKey()
  )
  await expectCodeAsync(
    () => decapsulateReThrowHarness.exportCipherKey(filledBytes(32, 1)),
    'BASE64URL_INVALID'
  )

  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        exportKey: async () => createA256CtrKey(),
      },
    })
  )

  const encapsulator = new EncapsulateKeyHarness(createMlKemPublicKey())
  encapsulator.params = {
    secretKey: filledBytes(ml_kem1024.lengths.secretKey, 9),
  }
  await expectCodeAsync(
    () => encapsulator.encapsulate(),
    'KEY_AGREEMENT_KEY_INVALID'
  )

  const decapsulator = new DecapsulateKeyHarness(createMlKemPrivateKey())
  decapsulator.params = {
    publicKey: filledBytes(ml_kem1024.lengths.publicKey, 9),
  }
  await expectCodeAsync(
    () =>
      decapsulator.decapsulate({
        ciphertext: new ArrayBuffer(ml_kem1024.lengths.cipherText),
      }),
    'KEY_AGREEMENT_KEY_INVALID'
  )

  const encapsulateFailHarness = new EncapsulateKeyHarness(
    createMlKemPublicKey()
  )
  encapsulateFailHarness.kem = {
    ...createImportKeyAlgorithmByAlgCode('ML-KEM-1024'),
    encapsulate() {
      throw new Error('boom')
    },
  }
  await expectCodeAsync(
    () => encapsulateFailHarness.encapsulate(),
    'ENCAPSULATION_FAILED'
  )

  const decapsulateFailHarness = new DecapsulateKeyHarness(
    createMlKemPrivateKey()
  )
  decapsulateFailHarness.kem = {
    ...createImportKeyAlgorithmByAlgCode('ML-KEM-1024'),
    decapsulate() {
      throw new Error('boom')
    },
  }
  await expectCodeAsync(
    () =>
      decapsulateFailHarness.decapsulate({
        ciphertext: new ArrayBuffer(ml_kem1024.lengths.cipherText),
      }),
    'DECAPSULATION_FAILED'
  )

  const hybridEncapsulateFailHarness = new EncapsulateKeyHarness(
    createX25519MlKem768PublicKey()
  )
  hybridEncapsulateFailHarness.kem = {
    ...createImportKeyAlgorithmByAlgCode('X25519-ML-KEM-768'),
    encapsulate() {
      throw new Error('boom')
    },
  }
  await expectCodeAsync(
    () => hybridEncapsulateFailHarness.encapsulate(),
    'ENCAPSULATION_FAILED'
  )

  const hybridDecapsulateFailHarness = new DecapsulateKeyHarness(
    createX25519MlKem768PrivateKey()
  )
  hybridDecapsulateFailHarness.kem = {
    ...createImportKeyAlgorithmByAlgCode('X25519-ML-KEM-768'),
    decapsulate() {
      throw new Error('boom')
    },
  }
  await expectCodeAsync(
    () =>
      hybridDecapsulateFailHarness.decapsulate({
        ciphertext: new ArrayBuffer(ml_kem768_x25519.lengths.cipherText),
      }),
    'DECAPSULATION_FAILED'
  )
})
