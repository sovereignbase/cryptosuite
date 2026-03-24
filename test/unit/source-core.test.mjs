import assert from 'node:assert/strict'
import test from 'node:test'
import { Cryptographic as SourceCryptographic } from '../../src/index.ts'
import * as cipherMessage from '../../src/CipherMessage/index.ts'
import * as digitalSignature from '../../src/DigitalSignature/index.ts'
import { CryptosuiteError } from '../../src/.errors/class.ts'
import { getBufferSourceLength } from '../../src/.helpers/getBufferSourceLength.ts'
import * as keyAgreement from '../../src/KeyAgreement/index.ts'
import * as messageAuthentication from '../../src/MessageAuthentication/index.ts'
import {
  expectCodeSync,
  restoreCrypto,
  setCrypto,
  buildCrypto,
} from '../support/index.mjs'

test.afterEach(() => {
  restoreCrypto()
})

test('source core exports expose the expected runtime surface', () => {
  assert.equal(typeof SourceCryptographic.identifier.generate, 'function')
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

test('getBufferSourceLength handles both supported inputs and rejects others', () => {
  assert.equal(getBufferSourceLength(new ArrayBuffer(7), 'x'), 7)
  assert.equal(getBufferSourceLength(new Uint8Array(9), 'x'), 9)
  expectCodeSync(
    () => getBufferSourceLength('x', 'boom'),
    'BUFFER_SOURCE_EXPECTED'
  )
})

test('source root surface remains usable when crypto is stubbed', async () => {
  setCrypto(
    buildCrypto({
      subtle: {
        digest: async () => new Uint8Array(48).buffer,
      },
    })
  )

  const id = await SourceCryptographic.identifier.derive(new Uint8Array([1, 2]))
  assert.equal(typeof id, 'string')
  assert.equal(id.length, 64)
})
