import assert from 'node:assert/strict'
import test from 'node:test'
import { webcrypto } from 'node:crypto'
import { createParamsByAlgCode } from '../../src/CipherMessage/.core/helpers/createParamsByAlgCode/index.ts'
import { getImportKeyAlgorithmByAlgCode } from '../../src/CipherMessage/.core/helpers/getImportKeyAlgorithmByAlgCode/index.ts'
import { getParamsByAlgCode } from '../../src/CipherMessage/.core/helpers/getParamsByAlgCode/index.ts'
import { validateKeyByAlgCode } from '../../src/CipherMessage/.core/helpers/validateKeyByAlgCode/index.ts'
import { CipherKeyHarness } from '../../src/CipherMessage/.core/CipherKeyHarness/class.ts'
import { deriveCipherKey } from '../../src/CipherMessage/deriveCipherKey/index.ts'
import {
  buildCrypto,
  expectCodeAsync,
  expectCodeSync,
  restoreCrypto,
  setCrypto,
} from '../support/index.mjs'
import {
  bytes,
  createA256CtrKey,
  createA256GcmKey,
} from '../support/fixtures.mjs'

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto
}

test.afterEach(() => {
  restoreCrypto()
})

test('source cipher helpers validate supported and unsupported algorithm branches', () => {
  expectCodeSync(() => validateKeyByAlgCode(null), 'CIPHER_KEY_INVALID')
  expectCodeSync(
    () => validateKeyByAlgCode(createA256CtrKey({ kty: 'AKP' })),
    'CIPHER_KEY_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createA256CtrKey({ use: 'sig' })),
    'CIPHER_KEY_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createA256CtrKey({ key_ops: 'encrypt' })),
    'CIPHER_KEY_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createA256CtrKey({ k: 'A' })),
    'BASE64URL_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createA256CtrKey({ k: 'AQ' })),
    'CIPHER_KEY_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createA256CtrKey({ alg: 'A128CTR' })),
    'ALGORITHM_UNSUPPORTED'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createA256GcmKey({ alg: 'A128GCM' })),
    'ALGORITHM_UNSUPPORTED'
  )

  const normalized = validateKeyByAlgCode(
    createA256CtrKey({ use: undefined, key_ops: undefined, extra: 'ok' })
  )
  assert.equal(normalized.use, 'enc')
  assert.deepEqual(normalized.key_ops, ['encrypt', 'decrypt'])
  assert.equal(normalized.extra, 'ok')

  const normalizedGcm = validateKeyByAlgCode(
    createA256GcmKey({ use: undefined, key_ops: undefined, extra: 'ok' })
  )
  assert.equal(normalizedGcm.alg, 'A256GCM')
  assert.deepEqual(normalizedGcm.key_ops, ['encrypt', 'decrypt'])
  assert.equal(normalizedGcm.extra, 'ok')
})

test('source cipher param helpers cover supported and unsupported branches', () => {
  setCrypto(
    buildCrypto({
      getRandomValues: (array) => array.fill(7),
    })
  )

  const params = createParamsByAlgCode('A256CTR')
  assert.equal(params.iv.byteLength, 12)
  assert.equal(params.iv[0], 7)
  const gcmParams = createParamsByAlgCode('A256GCM')
  assert.equal(gcmParams.iv.byteLength, 12)
  assert.equal(gcmParams.iv[0], 7)

  setCrypto({
    subtle: globalThis.crypto.subtle,
  })
  expectCodeSync(
    () => createParamsByAlgCode('A256CTR'),
    'GET_RANDOM_VALUES_UNAVAILABLE'
  )
  expectCodeSync(
    () => createParamsByAlgCode('A128CTR'),
    'ALGORITHM_UNSUPPORTED'
  )

  const importAlgorithm = getImportKeyAlgorithmByAlgCode('A256CTR')
  assert.equal(importAlgorithm.name, 'AES-CTR')
  const gcmImportAlgorithm = getImportKeyAlgorithmByAlgCode('A256GCM')
  assert.equal(gcmImportAlgorithm.name, 'AES-GCM')

  expectCodeSync(
    () => getImportKeyAlgorithmByAlgCode('A128CTR'),
    'ALGORITHM_UNSUPPORTED'
  )

  const webCryptoParams = getParamsByAlgCode('A256CTR', {
    iv: new Uint8Array(12).fill(9),
  })
  assert.equal(webCryptoParams.name, 'AES-CTR')
  assert.equal(webCryptoParams.counter.byteLength, 16)
  assert.equal(webCryptoParams.length, 32)
  const gcmWebCryptoParams = getParamsByAlgCode('A256GCM', {
    iv: new Uint8Array(12).fill(9),
  })
  assert.equal(gcmWebCryptoParams.name, 'AES-GCM')
  assert.equal(gcmWebCryptoParams.iv.byteLength, 12)
  assert.equal(gcmWebCryptoParams.tagLength, 128)

  expectCodeSync(
    () => getParamsByAlgCode('A256CTR', { iv: new ArrayBuffer(12) }),
    'CIPHER_MESSAGE_INVALID'
  )
  expectCodeSync(
    () => getParamsByAlgCode('A256GCM', { iv: new ArrayBuffer(12) }),
    'CIPHER_MESSAGE_INVALID'
  )
  expectCodeSync(
    () => getParamsByAlgCode('A256CTR', { iv: new Uint8Array(11) }),
    'CIPHER_MESSAGE_INVALID'
  )
  expectCodeSync(
    () => getParamsByAlgCode('A256GCM', { iv: new Uint8Array(11) }),
    'CIPHER_MESSAGE_INVALID'
  )
  expectCodeSync(
    () => getParamsByAlgCode('A128CTR', { iv: new Uint8Array(12) }),
    'ALGORITHM_UNSUPPORTED'
  )
})

test('source CipherKeyHarness covers constructor, import failure, and decrypt validation branches', async () => {
  setCrypto({})
  expectCodeSync(
    () => new CipherKeyHarness(createA256CtrKey()),
    'SUBTLE_UNAVAILABLE'
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
  const importFailHarness = new CipherKeyHarness(createA256CtrKey())
  await expectCodeAsync(
    () => importFailHarness.encrypt(bytes(1, 2, 3)),
    'ALGORITHM_UNSUPPORTED'
  )

  setCrypto(
    buildCrypto({
      getRandomValues: (array) => array.fill(3),
      subtle: {
        importKey: async () => ({}),
        encrypt: async () => bytes(4, 5, 6).buffer,
        decrypt: async () => bytes(7, 8, 9).buffer,
      },
    })
  )

  const harness = new CipherKeyHarness(createA256GcmKey())
  const encrypted = await harness.encrypt(bytes(1, 2, 3))
  assert.ok(encrypted.ciphertext instanceof ArrayBuffer)
  assert.equal(encrypted.iv.byteLength, 12)

  const decrypted = await harness.decrypt({
    ciphertext: new ArrayBuffer(3),
    iv: new Uint8Array(12).fill(4),
  })
  assert.deepEqual(Array.from(decrypted), [7, 8, 9])

  await expectCodeAsync(
    () => harness.decrypt({ iv: new Uint8Array(12) }),
    'CIPHER_MESSAGE_INVALID'
  )

  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        decrypt: async () => {
          throw new Error('auth fail')
        },
      },
    })
  )

  const decryptFailHarness = new CipherKeyHarness(createA256GcmKey())
  await expectCodeAsync(
    () =>
      decryptFailHarness.decrypt({
        ciphertext: new ArrayBuffer(3),
        iv: new Uint8Array(12).fill(4),
      }),
    'CIPHER_ARTIFACT_INVALID'
  )
})

test('source deriveCipherKey covers subtle-unavailable branch', async () => {
  setCrypto({})
  await expectCodeAsync(
    () => deriveCipherKey(bytes(1, 2, 3)),
    'SUBTLE_UNAVAILABLE'
  )
})

test('source deriveCipherKey covers generated-salt branch', async () => {
  setCrypto(
    buildCrypto({
      getRandomValues: (array) => array.fill(5),
      subtle: {
        importKey: async () => ({}),
        deriveKey: async () => ({}),
        exportKey: async () => createA256GcmKey(),
      },
    })
  )

  const result = await deriveCipherKey(bytes(1, 2, 3))
  assert.equal(result.cipherKey.alg, 'A256GCM')
  assert.deepEqual(Array.from(result.salt), Array(16).fill(5))
})
