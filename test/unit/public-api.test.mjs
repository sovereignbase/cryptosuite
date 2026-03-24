import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import test from 'node:test'
import { Cryptographic } from '../../dist/index.js'

test('Cryptographic exposes the current static API surface', () => {
  assert.equal(typeof Cryptographic.identifier.derive, 'function')
  assert.equal(typeof Cryptographic.identifier.generate, 'function')
  assert.equal(typeof Cryptographic.identifier.validate, 'function')
  assert.equal(typeof Cryptographic.cipherMessage.encrypt, 'function')
  assert.equal(typeof Cryptographic.cipherMessage.decrypt, 'function')
  assert.equal(typeof Cryptographic.cipherMessage.deriveKey, 'function')
  assert.equal(typeof Cryptographic.cipherMessage.generateKey, 'function')
  assert.equal(typeof Cryptographic.messageAuthentication.sign, 'function')
  assert.equal(typeof Cryptographic.messageAuthentication.verify, 'function')
  assert.equal(typeof Cryptographic.messageAuthentication.deriveKey, 'function')
  assert.equal(
    typeof Cryptographic.messageAuthentication.generateKey,
    'function'
  )
  assert.equal(typeof Cryptographic.keyAgreement.encapsulate, 'function')
  assert.equal(typeof Cryptographic.keyAgreement.decapsulate, 'function')
  assert.equal(typeof Cryptographic.keyAgreement.deriveKeypair, 'function')
  assert.equal(typeof Cryptographic.keyAgreement.generateKeypair, 'function')
  assert.equal(typeof Cryptographic.digitalSignature.sign, 'function')
  assert.equal(typeof Cryptographic.digitalSignature.verify, 'function')
  assert.equal(typeof Cryptographic.digitalSignature.deriveKeypair, 'function')
  assert.equal(
    typeof Cryptographic.digitalSignature.generateKeypair,
    'function'
  )
})

test('Cryptographic CJS build exposes the same static API surface', () => {
  const require = createRequire(import.meta.url)
  const { Cryptographic: CjsCryptographic } = require('../../dist/index.cjs')

  assert.equal(typeof CjsCryptographic.identifier.derive, 'function')
  assert.equal(typeof CjsCryptographic.cipherMessage.encrypt, 'function')
  assert.equal(typeof CjsCryptographic.messageAuthentication.sign, 'function')
  assert.equal(typeof CjsCryptographic.keyAgreement.encapsulate, 'function')
  assert.equal(typeof CjsCryptographic.digitalSignature.sign, 'function')
})
