import assert from 'node:assert/strict'
import test from 'node:test'
import { webcrypto } from 'node:crypto'
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
  filledBytes,
} from '../support/fixtures.mjs'

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto
}

const ORIGINAL_ENCAPSULATE = ml_kem1024.encapsulate
const ORIGINAL_DECAPSULATE = ml_kem1024.decapsulate

test.afterEach(() => {
  restoreCrypto()
  ml_kem1024.encapsulate = ORIGINAL_ENCAPSULATE
  ml_kem1024.decapsulate = ORIGINAL_DECAPSULATE
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

  ml_kem1024.encapsulate = () => {
    throw new Error('boom')
  }
  const encapsulateFailHarness = new EncapsulateKeyHarness(
    createMlKemPublicKey()
  )
  await expectCodeAsync(
    () => encapsulateFailHarness.encapsulate(),
    'ENCAPSULATION_FAILED'
  )

  ml_kem1024.encapsulate = ORIGINAL_ENCAPSULATE
  ml_kem1024.decapsulate = () => {
    throw new Error('boom')
  }
  const decapsulateFailHarness = new DecapsulateKeyHarness(
    createMlKemPrivateKey()
  )
  await expectCodeAsync(
    () =>
      decapsulateFailHarness.decapsulate({
        ciphertext: new ArrayBuffer(ml_kem1024.lengths.cipherText),
      }),
    'DECAPSULATION_FAILED'
  )
})
