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
import { bytes } from '../support/fixtures.mjs'

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto
}

test.afterEach(() => {
  restoreCrypto()
})

test('identifier.generate returns a fixed-length opaque identifier', async () => {
  const identifier = await Cryptographic.identifier.generate()
  assert.equal(identifier.length, 64)
  assert.equal(Cryptographic.identifier.validate(identifier), identifier)
})

test('identifier.derive returns a deterministic opaque identifier', async () => {
  const source = bytes(1, 2, 3, 4)
  const one = await Cryptographic.identifier.derive(source)
  const two = await Cryptographic.identifier.derive(source)
  assert.equal(one, two)
  assert.equal(one.length, 64)
})

test('identifier.validate accepts only 64-char base64url strings', () => {
  const valid = 'A'.repeat(64)
  assert.equal(Cryptographic.identifier.validate(valid), valid)
  assert.equal(Cryptographic.identifier.validate('bad'), false)
  assert.equal(Cryptographic.identifier.validate('ä'.repeat(64)), false)
  assert.equal(Cryptographic.identifier.validate(123), false)
})

test('identifier.derive maps digest failures to SHA384_UNSUPPORTED', async () => {
  setCrypto(
    buildCrypto({
      subtle: {
        digest: async () => {
          throw new Error('no')
        },
      },
    })
  )

  await expectCodeAsync(
    () => Cryptographic.identifier.derive(bytes(9, 9, 9)),
    'SHA384_UNSUPPORTED'
  )
})
