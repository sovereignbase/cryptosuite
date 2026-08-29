import assert from 'node:assert/strict'
import { test } from 'vitest'
import { webcrypto } from 'node:crypto'
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js'
import { Cryptographic } from '../../dist/index.js'
import { bytes } from '../support/fixtures.mjs'

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto
}

const PLAINTEXT = new TextEncoder().encode('cryptosuite integration')

test('integration: AES-GCM encrypt/decrypt roundtrip', async () => {
  const cipherKey = await Cryptographic.cipherMessage.generateKey()
  const cipherMessage = await Cryptographic.cipherMessage.encrypt(
    cipherKey,
    PLAINTEXT
  )
  const plaintext = await Cryptographic.cipherMessage.decrypt(
    cipherKey,
    cipherMessage
  )
  assert.deepEqual(Array.from(plaintext), Array.from(PLAINTEXT))
  assert.equal(cipherMessage.iv.byteLength, 12)
})

test('integration: cipher derivation accepts an optional salt', async () => {
  const salt = new Uint8Array(16).fill(9)
  const one = await Cryptographic.cipherMessage.deriveKey(PLAINTEXT, salt)
  const two = await Cryptographic.cipherMessage.deriveKey(PLAINTEXT, salt)
  const unsalted = await Cryptographic.cipherMessage.deriveKey(PLAINTEXT)
  assert.equal(one.k, two.k)
  assert.notEqual(one.k, unsalted.k)
  assert.equal(one.alg, 'A256GCM')
})

test('integration: HMAC sign/verify roundtrip', async () => {
  const key = await Cryptographic.messageAuthentication.generateKey()
  const signature = await Cryptographic.messageAuthentication.sign(
    key,
    PLAINTEXT
  )
  const verified = await Cryptographic.messageAuthentication.verify(
    key,
    PLAINTEXT,
    signature
  )
  const rejected = await Cryptographic.messageAuthentication.verify(
    key,
    bytes(0, ...PLAINTEXT),
    signature
  )

  assert.equal(verified, true)
  assert.equal(rejected, false)
})

test('integration: HMAC derivation accepts an optional salt', async () => {
  const material = bytes(1, 2, 3, 4, 5, 6, 7, 8)
  const salt = new Uint8Array(16).fill(7)
  const one = await Cryptographic.messageAuthentication.deriveKey(
    material,
    salt
  )
  const two = await Cryptographic.messageAuthentication.deriveKey(
    material,
    salt
  )
  const unsalted = await Cryptographic.messageAuthentication.deriveKey(material)
  assert.equal(one.k, two.k)
  assert.notEqual(one.k, unsalted.k)
  assert.equal(one.alg, 'HS256')
})

test('integration: key agreement encapsulate/decapsulate reconstructs the same cipher key', async () => {
  const { encapsulateKey, decapsulateKey } =
    await Cryptographic.keyAgreement.generateKeypair()
  const { keyOffer, cipherKey: localCipherKey } =
    await Cryptographic.keyAgreement.encapsulate(encapsulateKey)
  const { cipherKey: remoteCipherKey } =
    await Cryptographic.keyAgreement.decapsulate(keyOffer, decapsulateKey)

  assert.equal(localCipherKey.k, remoteCipherKey.k)

  const cipherMessage = await Cryptographic.cipherMessage.encrypt(
    localCipherKey,
    PLAINTEXT
  )
  const plaintext = await Cryptographic.cipherMessage.decrypt(
    remoteCipherKey,
    cipherMessage
  )
  assert.deepEqual(Array.from(plaintext), Array.from(PLAINTEXT))
})

test('integration: key agreement derivation is deterministic', async () => {
  const seed = new Uint8Array(ml_kem768_x25519.lengths.seed).fill(11)
  const one = await Cryptographic.keyAgreement.deriveKeypair(seed)
  const two = await Cryptographic.keyAgreement.deriveKeypair(seed)
  assert.equal(one.encapsulateKey.x, two.encapsulateKey.x)
  assert.equal(one.decapsulateKey.d, two.decapsulateKey.d)
})

test('integration: digital signature sign/verify roundtrip', async () => {
  const { signKey, verifyKey } =
    await Cryptographic.digitalSignature.generateKeypair()
  const signature = await Cryptographic.digitalSignature.sign(
    signKey,
    PLAINTEXT
  )
  const verified = await Cryptographic.digitalSignature.verify(
    verifyKey,
    PLAINTEXT,
    signature
  )
  const rejected = await Cryptographic.digitalSignature.verify(
    verifyKey,
    bytes(255, ...PLAINTEXT),
    signature
  )

  assert.equal(verified, true)
  assert.equal(rejected, false)
})

test('integration: digital signature derivation is deterministic', async () => {
  const seed = new Uint8Array(64).fill(12)
  const one = await Cryptographic.digitalSignature.deriveKeypair(seed)
  const two = await Cryptographic.digitalSignature.deriveKeypair(seed)
  assert.equal(one.signKey.d, two.signKey.d)
  assert.equal(one.verifyKey.x, two.verifyKey.x)
})
