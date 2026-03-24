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
  createMlDsaSignKey,
  createMlDsaVerifyKey,
  filledBytes,
} from '../support/fixtures.mjs'

const ORIGINAL_SIGN = ml_dsa87.sign
const ORIGINAL_VERIFY = ml_dsa87.verify

test.afterEach(() => {
  ml_dsa87.sign = ORIGINAL_SIGN
  ml_dsa87.verify = ORIGINAL_VERIFY
})

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

  ml_dsa87.sign = () => {
    throw new Error('boom')
  }
  await expectCodeAsync(
    () => new SignKeyHarness(createMlDsaSignKey()).sign(bytes(1, 2, 3)),
    'ALGORITHM_UNSUPPORTED'
  )

  ml_dsa87.sign = ORIGINAL_SIGN
  ml_dsa87.verify = () => {
    throw new Error('boom')
  }
  await expectCodeAsync(
    () =>
      new VerifyKeyHarness(createMlDsaVerifyKey()).verify(
        bytes(1, 2, 3),
        bytes(4, 5, 6)
      ),
    'ALGORITHM_UNSUPPORTED'
  )
})
