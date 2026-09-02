import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { test } from 'vitest'
import { Cryptographic } from '../../dist/index.js'

test('Cryptographic exposes the current static API surface', () => {
  assert.equal(typeof Cryptographic.identifier.generate, 'function')
  assert.equal(typeof Cryptographic.identifier.derive, 'function')
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

  assert.equal(typeof CjsCryptographic.identifier.generate, 'function')
  assert.equal(typeof CjsCryptographic.cipherMessage.encrypt, 'function')
  assert.equal(typeof CjsCryptographic.messageAuthentication.sign, 'function')
  assert.equal(typeof CjsCryptographic.keyAgreement.encapsulate, 'function')
  assert.equal(typeof CjsCryptographic.digitalSignature.sign, 'function')
})

test('ESM package subpaths expose each focused API', async () => {
  const cipherMessage = await import('@sovereignbase/cryptosuite/CipherMessage')
  const digitalSignature =
    await import('@sovereignbase/cryptosuite/DigitalSignature')
  const identifier = await import('@sovereignbase/cryptosuite/Identifier')
  const keyAgreement = await import('@sovereignbase/cryptosuite/KeyAgreement')
  const messageAuthentication =
    await import('@sovereignbase/cryptosuite/MessageAuthentication')

  assert.equal(typeof cipherMessage.CipherCluster, 'function')
  assert.equal(typeof cipherMessage.deriveCipherKey, 'function')
  assert.equal(typeof cipherMessage.generateCipherKey, 'function')
  assert.equal(typeof digitalSignature.DigitalSignatureCluster, 'function')
  assert.equal(
    typeof digitalSignature.deriveDigitalSignatureKeypair,
    'function'
  )
  assert.equal(
    typeof digitalSignature.generateDigitalSignatureKeypair,
    'function'
  )
  assert.equal(typeof identifier.Identifier, 'function')
  assert.equal(typeof keyAgreement.KeyAgreementCluster, 'function')
  assert.equal(typeof keyAgreement.deriveKeyAgreementKeypair, 'function')
  assert.equal(typeof keyAgreement.generateKeyAgreementKeypair, 'function')
  assert.equal(
    typeof messageAuthentication.MessageAuthenticationCluster,
    'function'
  )
  assert.equal(
    typeof messageAuthentication.deriveMessageAuthenticationKey,
    'function'
  )
  assert.equal(
    typeof messageAuthentication.generateMessageAuthenticationKey,
    'function'
  )
})

test('CJS package subpaths expose each focused API', () => {
  const require = createRequire(import.meta.url)

  assert.equal(
    typeof require('@sovereignbase/cryptosuite/CipherMessage').CipherCluster,
    'function'
  )
  assert.equal(
    typeof require('@sovereignbase/cryptosuite/DigitalSignature')
      .DigitalSignatureCluster,
    'function'
  )
  assert.equal(
    typeof require('@sovereignbase/cryptosuite/Identifier').Identifier,
    'function'
  )
  assert.equal(
    typeof require('@sovereignbase/cryptosuite/KeyAgreement')
      .KeyAgreementCluster,
    'function'
  )
  assert.equal(
    typeof require('@sovereignbase/cryptosuite/MessageAuthentication')
      .MessageAuthenticationCluster,
    'function'
  )
})
