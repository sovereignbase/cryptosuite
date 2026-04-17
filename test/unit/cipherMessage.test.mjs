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
  createA256GcmKey,
} from '../support/fixtures.mjs'

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto
}

test.afterEach(() => {
  restoreCrypto()
})

test('cipherMessage.generateKey throws when crypto.subtle is unavailable', async () => {
  setCrypto({})
  await expectCodeAsync(
    () => Cryptographic.cipherMessage.generateKey(),
    'SUBTLE_UNAVAILABLE'
  )
})

test('cipherMessage.generateKey maps unsupported AES-GCM to ALGORITHM_UNSUPPORTED', async () => {
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
    () => Cryptographic.cipherMessage.generateKey(),
    'ALGORITHM_UNSUPPORTED'
  )
})

test('cipherMessage.deriveKey rejects empty source key material', async () => {
  await expectCodeAsync(
    () => Cryptographic.cipherMessage.deriveKey(new Uint8Array(0)),
    'CIPHER_KEY_INVALID'
  )
})

test('cipherMessage.deriveKey requires getRandomValues when salt is omitted', async () => {
  setCrypto(
    buildCrypto({
      getRandomValues: undefined,
    })
  )

  await expectCodeAsync(
    () => Cryptographic.cipherMessage.deriveKey(bytes(1, 2, 3)),
    'GET_RANDOM_VALUES_UNAVAILABLE'
  )
})

test('cipherMessage.deriveKey maps unsupported HKDF or AES-GCM to ALGORITHM_UNSUPPORTED', async () => {
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
    () =>
      Cryptographic.cipherMessage.deriveKey(bytes(1, 2, 3), {
        salt: new Uint8Array(16),
      }),
    'ALGORITHM_UNSUPPORTED'
  )
})

test('cipherMessage encrypt/decrypt accepts a minimal valid JWK without optional props', async () => {
  setCrypto(
    buildCrypto({
      getRandomValues: (array) => array.fill(7),
      subtle: {
        importKey: async () => ({}),
        encrypt: async () => bytes(4, 5, 6).buffer,
        decrypt: async () => bytes(1, 2, 3).buffer,
      },
    })
  )

  const cipherKey = createA256GcmKey({
    use: undefined,
    key_ops: undefined,
  })
  const cipherMessage = await Cryptographic.cipherMessage.encrypt(
    cipherKey,
    bytes(1, 2, 3)
  )
  assert.ok(cipherMessage.ciphertext instanceof ArrayBuffer)
  assert.equal(cipherMessage.iv.byteLength, 12)

  const plaintext = await Cryptographic.cipherMessage.decrypt(
    cipherKey,
    cipherMessage
  )
  assert.deepEqual(Array.from(plaintext), [1, 2, 3])
})

test('cipherMessage.encrypt rejects malformed cipher keys', async () => {
  await expectCodeAsync(
    () =>
      Cryptographic.cipherMessage.encrypt(
        createA256CtrKey({
          alg: 'A256GCM',
          k: 'A',
        }),
        bytes(1)
      ),
    'BASE64URL_INVALID'
  )
})

test('cipherMessage.encrypt still accepts malformed historical AES-CTR keys as validation failures', async () => {
  await expectCodeAsync(
    () =>
      Cryptographic.cipherMessage.encrypt(
        createA256CtrKey({
          k: 'A',
        }),
        bytes(1)
      ),
    'BASE64URL_INVALID'
  )
})

test('cipherMessage.encrypt rejects unsupported cipher alg codes', async () => {
  await expectCodeAsync(
    () =>
      Cryptographic.cipherMessage.encrypt(
        createA256GcmKey({
          alg: 'A128GCM',
        }),
        bytes(1)
      ),
    'ALGORITHM_UNSUPPORTED'
  )
})

test('cipherMessage.decrypt rejects malformed cipher message artifacts', async () => {
  await expectCodeAsync(
    () =>
      Cryptographic.cipherMessage.decrypt(createA256GcmKey(), {
        iv: new Uint8Array(12),
      }),
    'CIPHER_MESSAGE_INVALID'
  )
})

test('cipherMessage.decrypt rejects invalid AES-GCM iv lengths', async () => {
  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
      },
    })
  )

  await expectCodeAsync(
    () =>
      Cryptographic.cipherMessage.decrypt(createA256GcmKey(), {
        ciphertext: new ArrayBuffer(1),
        iv: new Uint8Array(11),
      }),
    'CIPHER_MESSAGE_INVALID'
  )
})

test('cipherMessage.decrypt still rejects invalid historical AES-CTR iv lengths', async () => {
  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
      },
    })
  )

  await expectCodeAsync(
    () =>
      Cryptographic.cipherMessage.decrypt(createA256CtrKey(), {
        ciphertext: new ArrayBuffer(1),
        iv: new Uint8Array(11),
      }),
    'CIPHER_MESSAGE_INVALID'
  )
})
