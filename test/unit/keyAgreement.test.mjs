import assert from 'node:assert/strict'
import test from 'node:test'
import { webcrypto } from 'node:crypto'
import { Cryptographic } from '../../dist/index.js'
import {
  buildCrypto,
  expectCodeAsync,
  restoreCrypto,
  setCrypto,
} from '../support/index.mjs'
import {
  bytes,
  createA256CtrKey,
  createMlKemPublicKey,
} from '../support/fixtures.mjs'

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto
}

test.afterEach(() => {
  restoreCrypto()
})

test('keyAgreement.deriveKeypair rejects seed lengths that do not match X25519-ML-KEM-768', async () => {
  await expectCodeAsync(
    () => Cryptographic.keyAgreement.deriveKeypair(bytes(1, 2, 3)),
    'KEY_AGREEMENT_KEY_INVALID'
  )
})

test('keyAgreement.encapsulate rejects malformed public key material', async () => {
  await expectCodeAsync(
    () =>
      Cryptographic.keyAgreement.encapsulate(
        createMlKemPublicKey({
          x: 'A',
        })
      ),
    'BASE64URL_INVALID'
  )
})

test('keyAgreement.encapsulate accepts a minimal public key without key_ops', async () => {
  const { encapsulateKey } = await Cryptographic.keyAgreement.generateKeypair()
  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        exportKey: async () => createA256CtrKey(),
      },
    })
  )

  const result = await Cryptographic.keyAgreement.encapsulate({
    ...encapsulateKey,
    key_ops: undefined,
  })
  assert.ok(result.keyOffer.ciphertext instanceof ArrayBuffer)
  assert.equal(result.cipherKey.alg, 'A256CTR')
})

test('keyAgreement.encapsulate maps shared-secret export failures to ENCAPSULATION_FAILED', async () => {
  const { encapsulateKey } = await Cryptographic.keyAgreement.generateKeypair()
  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => {
          throw new Error('no')
        },
      },
    })
  )

  await expectCodeAsync(
    () => Cryptographic.keyAgreement.encapsulate(encapsulateKey),
    'ENCAPSULATION_FAILED'
  )
})

test('keyAgreement.decapsulate rejects malformed key offer artifacts', async () => {
  const { decapsulateKey } = await Cryptographic.keyAgreement.generateKeypair()
  await expectCodeAsync(
    () => Cryptographic.keyAgreement.decapsulate({}, decapsulateKey),
    'KEY_AGREEMENT_ARTIFACT_INVALID'
  )
})

test('keyAgreement.decapsulate rejects ciphertexts with invalid lengths', async () => {
  const { decapsulateKey } = await Cryptographic.keyAgreement.generateKeypair()
  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        exportKey: async () => createA256CtrKey(),
      },
    })
  )

  await expectCodeAsync(
    () =>
      Cryptographic.keyAgreement.decapsulate(
        {
          ciphertext: new ArrayBuffer(1),
        },
        decapsulateKey
      ),
    'KEY_AGREEMENT_ARTIFACT_INVALID'
  )
})

test('keyAgreement.decapsulate accepts a minimal private key without key_ops', async () => {
  const { encapsulateKey, decapsulateKey } =
    await Cryptographic.keyAgreement.generateKeypair()
  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        exportKey: async () => createA256CtrKey(),
      },
    })
  )

  const { keyOffer } =
    await Cryptographic.keyAgreement.encapsulate(encapsulateKey)
  const result = await Cryptographic.keyAgreement.decapsulate(keyOffer, {
    ...decapsulateKey,
    key_ops: undefined,
  })
  assert.equal(result.cipherKey.alg, 'A256CTR')
})

test('keyAgreement cluster reuses cached harnesses for the same key objects', async () => {
  const { encapsulateKey, decapsulateKey } =
    await Cryptographic.keyAgreement.generateKeypair()
  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        exportKey: async () => createA256CtrKey(),
      },
    })
  )

  const first = await Cryptographic.keyAgreement.encapsulate(encapsulateKey)
  const second = await Cryptographic.keyAgreement.encapsulate(encapsulateKey)
  assert.equal(first.cipherKey.alg, 'A256CTR')
  assert.equal(second.cipherKey.alg, 'A256CTR')

  const third = await Cryptographic.keyAgreement.decapsulate(
    first.keyOffer,
    decapsulateKey
  )
  const fourth = await Cryptographic.keyAgreement.decapsulate(
    second.keyOffer,
    decapsulateKey
  )
  assert.equal(third.cipherKey.alg, 'A256CTR')
  assert.equal(fourth.cipherKey.alg, 'A256CTR')
})
