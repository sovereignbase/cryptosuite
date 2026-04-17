import assert from 'node:assert/strict'
import test from 'node:test'
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { createImportKeyAlgorithmByAlgCode } from '../../src/DigitalSignature/.core/helpers/createImportKeyAlgorithmByAlgCode/index.ts'
import { createParamsByAlgCode } from '../../src/DigitalSignature/.core/helpers/createParamsByAlgCode/index.ts'
import { getParamsByAlgCode } from '../../src/DigitalSignature/.core/helpers/getParamsByAlgCode/index.ts'
import { validateKeyByAlgCode } from '../../src/DigitalSignature/.core/helpers/validateKeyByAlgCode/index.ts'
import { SignKeyHarness } from '../../src/DigitalSignature/.core/SignKeyHarness/class.ts'
import { VerifyKeyHarness } from '../../src/DigitalSignature/.core/VerifyKeyHarness/class.ts'
import { expectCodeAsync, expectCodeSync } from '../support/index.mjs'
import {
  bytes,
  createEd25519MlDsa65SignKey,
  createEd25519MlDsa65VerifyKey,
  createMlDsaSignKey,
  createMlDsaVerifyKey,
  filledBytes,
} from '../support/fixtures.mjs'

test('source digital signature helpers cover validation and unsupported branches', () => {
  expectCodeSync(() => validateKeyByAlgCode(null), 'SIGN_JWK_INVALID')
  expectCodeSync(
    () => validateKeyByAlgCode(createMlDsaSignKey({ kty: 'oct' })),
    'SIGN_JWK_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createMlDsaSignKey({ use: 'enc' })),
    'SIGN_JWK_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createMlDsaSignKey({ key_ops: ['verify'] })),
    'SIGN_JWK_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createMlDsaSignKey({ d: 'A' })),
    'BASE64URL_INVALID'
  )
  expectCodeSync(
    () =>
      validateKeyByAlgCode(
        createMlDsaSignKey({
          d: Buffer.from([1]).toString('base64url'),
        })
      ),
    'SIGN_JWK_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createMlDsaVerifyKey({ key_ops: ['sign'] })),
    'VERIFY_JWK_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createMlDsaVerifyKey({ x: 'A' })),
    'BASE64URL_INVALID'
  )
  expectCodeSync(
    () =>
      validateKeyByAlgCode(
        createMlDsaVerifyKey({
          x: Buffer.from([1]).toString('base64url'),
        })
      ),
    'VERIFY_JWK_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode({ kty: 'AKP', alg: 'ML-DSA-87' }),
    'SIGN_JWK_INVALID'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createMlDsaSignKey({ alg: 'ML-DSA-65' })),
    'ALGORITHM_UNSUPPORTED'
  )
  expectCodeSync(
    () => validateKeyByAlgCode(createEd25519MlDsa65SignKey({ kty: 'oct' })),
    'SIGN_JWK_INVALID'
  )
  expectCodeSync(
    () =>
      validateKeyByAlgCode(
        createEd25519MlDsa65SignKey({
          d: Buffer.from([1]).toString('base64url'),
        })
      ),
    'SIGN_JWK_INVALID'
  )
  expectCodeSync(
    () =>
      validateKeyByAlgCode(
        createEd25519MlDsa65VerifyKey({
          x: Buffer.from([1]).toString('base64url'),
        })
      ),
    'VERIFY_JWK_INVALID'
  )

  const normalizedSign = validateKeyByAlgCode(
    createMlDsaSignKey({ key_ops: undefined, extra: 'ok' })
  )
  assert.equal(normalizedSign.use, 'sig')
  assert.deepEqual(normalizedSign.key_ops, ['sign'])
  assert.equal(normalizedSign.extra, 'ok')

  const normalizedVerify = validateKeyByAlgCode(
    createMlDsaVerifyKey({ key_ops: undefined, extra: 'ok' })
  )
  assert.equal(normalizedVerify.use, 'sig')
  assert.deepEqual(normalizedVerify.key_ops, ['verify'])
  assert.equal(normalizedVerify.extra, 'ok')

  assert.equal(createImportKeyAlgorithmByAlgCode('ML-DSA-87'), ml_dsa87)
  const hybridAlgorithm = createImportKeyAlgorithmByAlgCode('Ed25519-ML-DSA-65')
  assert.equal(hybridAlgorithm.lengths.secretKey, 64)
  expectCodeSync(
    () => createImportKeyAlgorithmByAlgCode('ML-DSA-65'),
    'ALGORITHM_UNSUPPORTED'
  )

  const signParams = createParamsByAlgCode(createMlDsaSignKey())
  assert.equal(signParams.secretKey.byteLength, ml_dsa87.lengths.secretKey)
  const verifyParams = createParamsByAlgCode(createMlDsaVerifyKey())
  assert.equal(verifyParams.publicKey.byteLength, ml_dsa87.lengths.publicKey)
  expectCodeSync(() => createParamsByAlgCode({}), 'SIGN_JWK_INVALID')

  assert.equal(getParamsByAlgCode('ML-DSA-87', signParams), signParams)
  expectCodeSync(
    () => getParamsByAlgCode('ML-DSA-65', signParams),
    'ALGORITHM_UNSUPPORTED'
  )
  const hybridSignParams = createParamsByAlgCode(createEd25519MlDsa65SignKey())
  assert.equal(
    hybridSignParams.secretKey.byteLength,
    hybridAlgorithm.lengths.secretKey
  )
  const hybridVerifyParams = createParamsByAlgCode(
    createEd25519MlDsa65VerifyKey()
  )
  assert.equal(
    hybridVerifyParams.publicKey.byteLength,
    hybridAlgorithm.lengths.publicKey
  )
  assert.equal(
    getParamsByAlgCode('Ed25519-ML-DSA-65', hybridSignParams),
    hybridSignParams
  )
})

test('source digital signature harnesses cover constructor, invariant, and catch branches', async () => {
  expectCodeSync(
    () => new SignKeyHarness(createMlDsaVerifyKey()),
    'SIGN_JWK_INVALID'
  )
  expectCodeSync(
    () => new VerifyKeyHarness(createMlDsaSignKey()),
    'VERIFY_JWK_INVALID'
  )

  const signer = new SignKeyHarness(createMlDsaSignKey())
  signer.params = { publicKey: filledBytes(ml_dsa87.lengths.publicKey, 1) }
  await expectCodeAsync(() => signer.sign(bytes(1, 2, 3)), 'SIGN_JWK_INVALID')

  const verifier = new VerifyKeyHarness(createMlDsaVerifyKey())
  verifier.params = { secretKey: filledBytes(ml_dsa87.lengths.secretKey, 1) }
  await expectCodeAsync(
    () => verifier.verify(bytes(1, 2, 3), bytes(4, 5, 6)),
    'VERIFY_JWK_INVALID'
  )

  const failingMlDsaSigner = new SignKeyHarness(createMlDsaSignKey())
  failingMlDsaSigner.signer = {
    ...createImportKeyAlgorithmByAlgCode('ML-DSA-87'),
    sign() {
      throw new Error('boom')
    },
  }
  await expectCodeAsync(
    () => failingMlDsaSigner.sign(bytes(1, 2, 3)),
    'ALGORITHM_UNSUPPORTED'
  )

  const failingMlDsaVerifier = new VerifyKeyHarness(createMlDsaVerifyKey())
  failingMlDsaVerifier.verifier = {
    ...createImportKeyAlgorithmByAlgCode('ML-DSA-87'),
    verify() {
      throw new Error('boom')
    },
  }
  await expectCodeAsync(
    () => failingMlDsaVerifier.verify(bytes(1, 2, 3), bytes(4, 5, 6)),
    'ALGORITHM_UNSUPPORTED'
  )

  const failingHybridSigner = new SignKeyHarness(createEd25519MlDsa65SignKey())
  failingHybridSigner.signer = {
    ...createImportKeyAlgorithmByAlgCode('Ed25519-ML-DSA-65'),
    sign() {
      throw new Error('boom')
    },
  }
  await expectCodeAsync(
    () => failingHybridSigner.sign(bytes(1, 2, 3)),
    'ALGORITHM_UNSUPPORTED'
  )

  const failingHybridVerifier = new VerifyKeyHarness(
    createEd25519MlDsa65VerifyKey()
  )
  failingHybridVerifier.verifier = {
    ...createImportKeyAlgorithmByAlgCode('Ed25519-ML-DSA-65'),
    verify() {
      throw new Error('boom')
    },
  }
  await expectCodeAsync(
    () => failingHybridVerifier.verify(bytes(1, 2, 3), bytes(4, 5, 6)),
    'ALGORITHM_UNSUPPORTED'
  )
})
