import assert from 'node:assert/strict'
import test from 'node:test'
import { webcrypto } from 'node:crypto'
import {
  generateCipherKey,
  deriveCipherKey,
  CipherAgent,
  CipherCluster,
  generateHMACKey,
  deriveHMACKey,
  HMACAgent,
  HMACCluster,
  generateExchangePair,
  WrapAgent,
  UnwrapAgent,
  ExchangeCluster,
  generateVerificationPair,
  SignAgent,
  VerifyAgent,
  VerificationCluster,
  generateOID,
  deriveOID,
  validateOID,
  Cryptosuite,
} from '../../dist/index.js'

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto
}

const PLAINTEXT = new Uint8Array([1, 2, 3, 4, 5, 6])

test('Cryptosuite static API is wired', () => {
  assert.equal(typeof Cryptosuite.cipher.encrypt, 'function')
  assert.equal(typeof Cryptosuite.exchange.wrap, 'function')
  assert.equal(typeof Cryptosuite.hmac.sign, 'function')
  assert.equal(typeof Cryptosuite.oid.generate, 'function')
  assert.equal(typeof Cryptosuite.verification.sign, 'function')
})

test('AES-GCM encrypt/decrypt roundtrip', async () => {
  const cipherJwk = await generateCipherKey()
  const agent = new CipherAgent(cipherJwk)
  const encrypted = await agent.encrypt(PLAINTEXT)
  const decrypted = await agent.decrypt(encrypted)
  assert.deepEqual(Array.from(decrypted), Array.from(PLAINTEXT))

  // cluster path and cache
  const artifact1 = await CipherCluster.encrypt(cipherJwk, PLAINTEXT)
  const artifact2 = await CipherCluster.encrypt(cipherJwk, PLAINTEXT)
  assert.ok(artifact1.iv instanceof Uint8Array)
  assert.ok(artifact1.ciphertext instanceof ArrayBuffer)
  const roundtrip = await CipherCluster.decrypt(cipherJwk, artifact2)
  assert.deepEqual(Array.from(roundtrip), Array.from(PLAINTEXT))
})

test('deriveCipherKey imports raw keys deterministically', async () => {
  const raw = new Uint8Array(32).fill(9)
  const derived1 = await deriveCipherKey(raw)
  const derived2 = await deriveCipherKey(raw)
  const customSalt = new Uint8Array(32).fill(7)
  const derived3 = await deriveCipherKey(raw, { salt: customSalt })
  const derived4 = await deriveCipherKey(raw, { salt: customSalt })
  assert.equal(derived1.kty, 'oct')
  assert.equal(derived1.k, derived2.k)
  assert.equal(derived3.k, derived4.k)
  assert.notEqual(derived1.k, derived3.k)
})

test('HMAC sign/verify roundtrip', async () => {
  const hmacJwk = await generateHMACKey()
  const agent = new HMACAgent(hmacJwk)
  const sig = await agent.sign(PLAINTEXT)
  const ok = await agent.verify(PLAINTEXT, sig)
  assert.equal(ok, true)

  const clusterSig = await HMACCluster.sign(hmacJwk, PLAINTEXT)
  assert.ok(clusterSig instanceof ArrayBuffer)
  const clusterOk = await HMACCluster.verify(hmacJwk, PLAINTEXT, clusterSig)
  assert.equal(clusterOk, true)
})

test('deriveHMACKey imports raw keys deterministically', async () => {
  const raw = new Uint8Array(32).fill(7)
  const derived1 = await deriveHMACKey(raw)
  const derived2 = await deriveHMACKey(raw)
  assert.equal(derived1.kty, 'oct')
  assert.equal(derived1.k, derived2.k)
})

test('OID generate/derive/validate', async () => {
  const oid = await generateOID()
  assert.equal(validateOID(oid) !== false, true)
  assert.equal(validateOID('bad'), false)
  assert.equal(validateOID(123), false)

  const derived = await deriveOID(PLAINTEXT)
  assert.equal(validateOID(derived) !== false, true)
})

test('Ed25519 sign/verify if supported', async () => {
  try {
    const { signJwk, verifyJwk } = await generateVerificationPair()
    const signer = new SignAgent(signJwk)
    const verifier = new VerifyAgent(verifyJwk)
    const sig = await signer.sign(PLAINTEXT)
    const ok = await verifier.verify(PLAINTEXT, sig)
    assert.equal(ok, true)

    const clusterSig = await VerificationCluster.sign(signJwk, PLAINTEXT)
    const clusterSig2 = await VerificationCluster.sign(signJwk, PLAINTEXT)
    const clusterOk = await VerificationCluster.verify(
      verifyJwk,
      PLAINTEXT,
      clusterSig
    )
    const clusterOk2 = await VerificationCluster.verify(
      verifyJwk,
      PLAINTEXT,
      clusterSig2
    )
    assert.equal(clusterOk, true)
    assert.equal(clusterOk2, true)
  } catch (err) {
    assert.equal(err.code, 'ED25519_UNSUPPORTED')
  }
})

test('RSA wrap/unwrap if supported', async () => {
  try {
    const { wrapJwk, unwrapJwk } = await generateExchangePair()
    const cipherJwk = await generateCipherKey()
    const wrapper = new WrapAgent(wrapJwk)
    const unwrapper = new UnwrapAgent(unwrapJwk)

    const wrapped = await wrapper.wrap(cipherJwk)
    const unwrapped = await unwrapper.unwrap(wrapped)
    assert.equal(unwrapped.kty, 'oct')

    const clusterWrapped = await ExchangeCluster.wrap(wrapJwk, cipherJwk)
    const clusterWrapped2 = await ExchangeCluster.wrap(wrapJwk, cipherJwk)
    const clusterUnwrapped = await ExchangeCluster.unwrap(
      unwrapJwk,
      clusterWrapped
    )
    const clusterUnwrapped2 = await ExchangeCluster.unwrap(
      unwrapJwk,
      clusterWrapped2
    )
    assert.equal(clusterUnwrapped.k, cipherJwk.k)
    assert.equal(clusterUnwrapped2.k, cipherJwk.k)
  } catch (err) {
    assert.equal(err.code, 'RSA_OAEP_UNSUPPORTED')
  }
})
