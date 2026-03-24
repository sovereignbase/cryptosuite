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
import { bytes, createHs256Key } from '../support/fixtures.mjs'

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto
}

test.afterEach(() => {
  restoreCrypto()
})

test('messageAuthentication.generateKey throws when crypto.subtle is unavailable', async () => {
  setCrypto({})
  await expectCodeAsync(
    () => Cryptographic.messageAuthentication.generateKey(),
    'SUBTLE_UNAVAILABLE'
  )
})

test('messageAuthentication.generateKey maps unsupported HMAC to ALGORITHM_UNSUPPORTED', async () => {
  setCrypto(
    buildCrypto({
      subtle: {
        generateKey: async () => {
          throw new Error('no')
        },
      },
    })
  )

  await expectCodeAsync(
    () => Cryptographic.messageAuthentication.generateKey(),
    'ALGORITHM_UNSUPPORTED'
  )
})

test('messageAuthentication.deriveKey rejects empty source key material', async () => {
  await expectCodeAsync(
    () => Cryptographic.messageAuthentication.deriveKey(new Uint8Array(0)),
    'HMAC_JWK_INVALID'
  )
})

test('messageAuthentication.deriveKey requires getRandomValues when salt is omitted', async () => {
  setCrypto({
    subtle: globalThis.crypto.subtle,
  })

  await expectCodeAsync(
    () => Cryptographic.messageAuthentication.deriveKey(bytes(1, 2, 3)),
    'GET_RANDOM_VALUES_UNAVAILABLE'
  )
})

test('messageAuthentication.deriveKey maps unsupported HKDF or HMAC to ALGORITHM_UNSUPPORTED', async () => {
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
    () => Cryptographic.messageAuthentication.deriveKey(bytes(1, 2, 3)),
    'ALGORITHM_UNSUPPORTED'
  )
})

test('messageAuthentication sign/verify accepts a minimal valid JWK without optional props', async () => {
  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        sign: async () => bytes(9, 8, 7).buffer,
        verify: async () => true,
      },
    })
  )

  const key = createHs256Key({
    use: undefined,
    key_ops: undefined,
  })
  const signature = await Cryptographic.messageAuthentication.sign(
    key,
    bytes(1, 2, 3)
  )
  assert.ok(signature instanceof ArrayBuffer)

  const verified = await Cryptographic.messageAuthentication.verify(
    key,
    bytes(1, 2, 3),
    signature
  )
  assert.equal(verified, true)
})

test('messageAuthentication.sign rejects malformed HMAC key material', async () => {
  await expectCodeAsync(
    () =>
      Cryptographic.messageAuthentication.sign(
        createHs256Key({
          k: 'A',
        }),
        bytes(1)
      ),
    'BASE64URL_INVALID'
  )
})

test('messageAuthentication.sign rejects unsupported alg codes', async () => {
  await expectCodeAsync(
    () =>
      Cryptographic.messageAuthentication.sign(
        createHs256Key({
          alg: 'HS512',
        }),
        bytes(1)
      ),
    'ALGORITHM_UNSUPPORTED'
  )
})
