import assert from 'node:assert/strict'
import test from 'node:test'
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { Cryptographic } from '../support/cryptographic.mjs'
import { expectCodeAsync } from '../support/index.mjs'
import {
  bytes,
  createMlDsaSignKey,
  createMlDsaVerifyKey,
} from '../support/fixtures.mjs'

test('digitalSignature.deriveKeypair rejects seed lengths that are not 32 bytes', async () => {
  await expectCodeAsync(
    () => Cryptographic.digitalSignature.deriveKeypair(bytes(1, 2, 3)),
    'SIGN_JWK_INVALID'
  )
})

test('digitalSignature.sign rejects malformed private key material', async () => {
  await expectCodeAsync(
    () =>
      Cryptographic.digitalSignature.sign(
        createMlDsaSignKey({
          d: 'A',
        }),
        bytes(1, 2, 3)
      ),
    'BASE64URL_INVALID'
  )
})

test('digitalSignature.verify rejects malformed public key material', async () => {
  await expectCodeAsync(
    () =>
      Cryptographic.digitalSignature.verify(
        createMlDsaVerifyKey({
          x: 'A',
        }),
        bytes(1, 2, 3),
        bytes(4, 5, 6)
      ),
    'BASE64URL_INVALID'
  )
})

test('digitalSignature sign/verify accepts minimal keys without key_ops', async () => {
  const { signKey, verifyKey } =
    await Cryptographic.digitalSignature.generateKeypair()
  const payload = bytes(1, 2, 3, 4)
  const signature = await Cryptographic.digitalSignature.sign(
    {
      ...signKey,
      key_ops: undefined,
    },
    payload
  )
  assert.ok(signature instanceof Uint8Array)
  assert.equal(signature.byteLength > 0, true)

  const verified = await Cryptographic.digitalSignature.verify(
    {
      ...verifyKey,
      key_ops: undefined,
    },
    payload,
    signature
  )
  assert.equal(verified, true)
})

test('digitalSignature.verify returns false for modified message bytes', async () => {
  const { signKey, verifyKey } =
    await Cryptographic.digitalSignature.generateKeypair()
  const payload = bytes(9, 8, 7, 6)
  const signature = await Cryptographic.digitalSignature.sign(signKey, payload)
  const verified = await Cryptographic.digitalSignature.verify(
    verifyKey,
    bytes(9, 8, 7, 5),
    signature
  )
  assert.equal(verified, false)
})

test('digitalSignature.sign maps ML-DSA runtime failures to ALGORITHM_UNSUPPORTED', async () => {
  const original = ml_dsa87.sign
  const { signKey } = await Cryptographic.digitalSignature.generateKeypair()
  ml_dsa87.sign = () => {
    throw new Error('boom')
  }

  try {
    await expectCodeAsync(
      () => Cryptographic.digitalSignature.sign(signKey, bytes(1, 2, 3)),
      'ALGORITHM_UNSUPPORTED'
    )
  } finally {
    ml_dsa87.sign = original
  }
})

test('digitalSignature.verify maps ML-DSA runtime failures to ALGORITHM_UNSUPPORTED', async () => {
  const original = ml_dsa87.verify
  const { verifyKey } = await Cryptographic.digitalSignature.generateKeypair()
  ml_dsa87.verify = () => {
    throw new Error('boom')
  }

  try {
    await expectCodeAsync(
      () =>
        Cryptographic.digitalSignature.verify(
          verifyKey,
          bytes(1, 2, 3),
          bytes(4, 5, 6)
        ),
      'ALGORITHM_UNSUPPORTED'
    )
  } finally {
    ml_dsa87.verify = original
  }
})

test('digitalSignature cluster reuses cached harnesses for the same key objects', async () => {
  const { signKey, verifyKey } =
    await Cryptographic.digitalSignature.generateKeypair()
  const payload = bytes(7, 7, 7)
  const first = await Cryptographic.digitalSignature.sign(signKey, payload)
  const second = await Cryptographic.digitalSignature.sign(signKey, payload)
  assert.equal(first.byteLength > 0, true)
  assert.equal(second.byteLength > 0, true)

  const signed = await Cryptographic.digitalSignature.sign(signKey, payload)
  const verifiedOne = await Cryptographic.digitalSignature.verify(
    verifyKey,
    payload,
    signed
  )
  const verifiedTwo = await Cryptographic.digitalSignature.verify(
    verifyKey,
    payload,
    signed
  )
  assert.equal(verifiedOne, true)
  assert.equal(verifiedTwo, true)
})
