import assert from 'node:assert/strict'
import { afterEach, test } from 'vitest'
import { Cryptographic as SourceCryptographic } from '../../src/index.ts'
import * as cipherMessage from '../../src/CipherMessage/index.ts'
import * as digitalSignature from '../../src/DigitalSignature/index.ts'
import { CryptosuiteError } from '../../src/.errors/class.ts'
import { normalizeBytes } from '../../src/.helpers/normalizeBytes.ts'
import * as keyAgreement from '../../src/KeyAgreement/index.ts'
import * as messageAuthentication from '../../src/MessageAuthentication/index.ts'
import {
  expectCodeSync,
  restoreCrypto,
  setCrypto,
  buildCrypto,
} from '../support/index.mjs'

afterEach(() => {
  restoreCrypto()
})

test('source core exports expose the expected runtime surface', () => {
  assert.equal('identifier' in SourceCryptographic, false)
  assert.equal(typeof SourceCryptographic.cipherMessage.encrypt, 'function')
  assert.equal(
    typeof SourceCryptographic.messageAuthentication.sign,
    'function'
  )
  assert.equal(typeof SourceCryptographic.keyAgreement.encapsulate, 'function')
  assert.equal(
    typeof SourceCryptographic.digitalSignature.generateKeypair,
    'function'
  )

  assert.equal(typeof cipherMessage.CipherCluster.encrypt, 'function')
  assert.equal(typeof cipherMessage.deriveCipherKey, 'function')
  assert.equal(typeof cipherMessage.generateCipherKey, 'function')

  assert.equal(
    typeof messageAuthentication.MessageAuthenticationCluster.sign,
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

  assert.equal(typeof keyAgreement.KeyAgreementCluster.encapsulate, 'function')
  assert.equal(typeof keyAgreement.deriveKeyAgreementKeypair, 'function')
  assert.equal(typeof keyAgreement.generateKeyAgreementKeypair, 'function')

  assert.equal(typeof digitalSignature.DigitalSignatureCluster.sign, 'function')
  assert.equal(
    typeof digitalSignature.deriveDigitalSignatureKeypair,
    'function'
  )
  assert.equal(
    typeof digitalSignature.generateDigitalSignatureKeypair,
    'function'
  )
})

test('CryptosuiteError uses the default code detail when no message is provided', () => {
  const error = new CryptosuiteError('ALGORITHM_UNSUPPORTED')
  assert.equal(error.name, 'CryptosuiteError')
  assert.equal(error.code, 'ALGORITHM_UNSUPPORTED')
  assert.equal(
    error.message,
    '{@sovereignbase/cryptosuite} ALGORITHM_UNSUPPORTED'
  )
})

test('normalizeBytes returns independent Uint8Array values and rejects invalid input', () => {
  const source = new Uint8Array([1, 2, 3])
  const normalized = normalizeBytes(source, 'x')
  assert.ok(normalized instanceof Uint8Array)
  assert.deepEqual(Array.from(normalized), [1, 2, 3])
  assert.notEqual(normalized, source)
  assert.ok(normalizeBytes(new ArrayBuffer(7), 'x') instanceof Uint8Array)
  expectCodeSync(() => normalizeBytes('x', 'boom'), 'BUFFER_SOURCE_EXPECTED')
  expectCodeSync(
    () => normalizeBytes('x', 'boom', 'CIPHER_MESSAGE_INVALID'),
    'CIPHER_MESSAGE_INVALID'
  )
})
