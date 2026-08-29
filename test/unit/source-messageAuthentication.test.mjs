import assert from 'node:assert/strict'
import { afterEach, test } from 'vitest'
import { webcrypto } from 'node:crypto'
import { createImportKeyAlgorithmByAlgCode } from '../../src/MessageAuthentication/.core/helpers/createImportKeyAlgorithmByAlgCode/index.ts'
import { createParamsByAlgCode } from '../../src/MessageAuthentication/.core/helpers/createParamsByAlgCode/index.ts'
import { getParamsByAlgCode } from '../../src/MessageAuthentication/.core/helpers/getParamsByAlgCode/index.ts'
import { validateKeyByAlgCode } from '../../src/MessageAuthentication/.core/helpers/validateKeyByAlgCode/index.ts'
import { MessageAuthenticationKeyHarness } from '../../src/MessageAuthentication/.core/MessageAuthenticationKeyHarness/class.ts'
import { deriveMessageAuthenticationKey } from '../../src/MessageAuthentication/deriveMessageAuthenticationKey/index.ts'
import { generateMessageAuthenticationKey } from '../../src/MessageAuthentication/generateMessageAuthenticationKey/index.ts'
import {
  buildCrypto,
  expectCodeAsync,
  expectCodeSync,
  restoreCrypto,
  setCrypto,
} from '../support/index.mjs'
import { bytes, createHs256Key } from '../support/fixtures.mjs'

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto
}

afterEach(() => {
  restoreCrypto()
})

test('source message authentication helpers cover validation and unsupported branches', () => {
  expectCodeSync(() => validateKeyByAlgCode(null), 'HMAC_JWK_INVALID')
  expectCodeSync(
    () => validateKeyByAlgCode(createHs256Key({ kty: 'AKP' })),
    'HMAC_JWK_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createHs256Key({ use: 'enc' })),
    'HMAC_JWK_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createHs256Key({ key_ops: 'sign' })),
    'HMAC_JWK_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createHs256Key({ k: 'A' })),
    'BASE64URL_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createHs256Key({ k: 'AQID' })),
    'HMAC_JWK_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createHs256Key({ alg: 'HS512' })),
    'ALGORITHM_UNSUPPORTED'
  )

  const normalized = validateKeyByAlgCode(
    createHs256Key({ use: undefined, key_ops: undefined, extra: 'ok' })
  )
  assert.equal(normalized.use, 'sig')
  assert.deepEqual(normalized.key_ops, ['sign', 'verify'])
  assert.equal(normalized.extra, 'ok')

  const importAlgorithm = createImportKeyAlgorithmByAlgCode('HS256')
  assert.equal(importAlgorithm.name, 'HMAC')
  assert.equal(importAlgorithm.hash, 'SHA-256')
  assert.deepEqual(createParamsByAlgCode('HS256'), {})
  assert.equal(getParamsByAlgCode('HS256', {}), 'HMAC')

  expectCodeSync(
    () => createImportKeyAlgorithmByAlgCode('HS512'),
    'ALGORITHM_UNSUPPORTED'
  )
  expectCodeSync(() => createParamsByAlgCode('HS512'), 'ALGORITHM_UNSUPPORTED')
  expectCodeSync(() => getParamsByAlgCode('HS512', {}), 'ALGORITHM_UNSUPPORTED')
})

test('source MessageAuthenticationKeyHarness covers subtle-unavailable and import failure branches', async () => {
  setCrypto({})
  expectCodeSync(
    () => new MessageAuthenticationKeyHarness(createHs256Key()),
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
  const importFailHarness = new MessageAuthenticationKeyHarness(
    createHs256Key()
  )
  await expectCodeAsync(
    () => importFailHarness.sign(bytes(1, 2, 3)),
    'ALGORITHM_UNSUPPORTED'
  )

  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        sign: async () => bytes(9, 8, 7).buffer,
        verify: async () => true,
      },
    })
  )
  const harness = new MessageAuthenticationKeyHarness(createHs256Key())
  const signature = await harness.sign(bytes(1, 2, 3))
  assert.ok(signature instanceof ArrayBuffer)
  const verified = await harness.verify(bytes(1, 2, 3), signature)
  assert.equal(verified, true)
})

test('source deriveMessageAuthenticationKey covers subtle-unavailable branch', async () => {
  setCrypto(undefined)
  await expectCodeAsync(
    () => deriveMessageAuthenticationKey(bytes(1, 2, 3)),
    'SUBTLE_UNAVAILABLE'
  )

  setCrypto({})
  await expectCodeAsync(
    () => deriveMessageAuthenticationKey(bytes(1, 2, 3)),
    'SUBTLE_UNAVAILABLE'
  )
})

test('source generateMessageAuthenticationKey returns the normalized default key', async () => {
  setCrypto({})
  await expectCodeAsync(
    () => generateMessageAuthenticationKey(),
    'SUBTLE_UNAVAILABLE'
  )

  setCrypto(
    buildCrypto({
      subtle: {
        generateKey: async () => ({}),
        exportKey: async () => createHs256Key(),
      },
    })
  )

  const key = await generateMessageAuthenticationKey()
  assert.equal(key.alg, 'HS256')
})

test('source deriveMessageAuthenticationKey uses optional salt and fixed domain info', async () => {
  const derivationParams = []
  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        deriveKey: async (params) => {
          derivationParams.push(params)
          return {}
        },
        exportKey: async () => createHs256Key(),
      },
    })
  )

  await expectCodeAsync(
    () => deriveMessageAuthenticationKey(new Uint8Array()),
    'HMAC_JWK_INVALID'
  )

  const unsalted = await deriveMessageAuthenticationKey(bytes(1, 2, 3))
  const salted = await deriveMessageAuthenticationKey(
    bytes(1, 2, 3),
    bytes(4, 5)
  )

  assert.equal(unsalted.alg, 'HS256')
  assert.equal(salted.alg, 'HS256')
  assert.equal(derivationParams[0].salt.byteLength, 0)
  assert.equal(
    new TextDecoder().decode(derivationParams[0].info),
    '@sovereignbase/cryptosuite/MessageAuthenticationKey'
  )
  assert.deepEqual(Array.from(derivationParams[1].salt), [4, 5])
  assert.deepEqual(
    Array.from(derivationParams[1].info),
    Array.from(derivationParams[0].info)
  )
})
