import assert from 'node:assert/strict'
import test from 'node:test'
import { webcrypto } from 'node:crypto'
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { toBase64UrlString } from '@sovereignbase/bytecodec'
import { loadDistInternals } from '../support/loadDistInternals.mjs'
import {
  buildCrypto,
  expectCodeAsync,
  expectCodeSync,
  restoreCrypto,
  setCrypto,
} from '../support/index.mjs'
import {
  bytes,
  createA256CtrKey,
  createHs256Key,
  createMlDsaSignKey,
  createMlDsaVerifyKey,
  createMlKemPrivateKey,
  createMlKemPublicKey,
  filledBytes,
} from '../support/fixtures.mjs'

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto
}

const ORIGINAL_ML_DSA_SIGN = ml_dsa87.sign
const ORIGINAL_ML_DSA_VERIFY = ml_dsa87.verify
const ORIGINAL_ML_KEM_ENCAPSULATE = ml_kem1024.encapsulate
const ORIGINAL_ML_KEM_DECAPSULATE = ml_kem1024.decapsulate

test.afterEach(async () => {
  restoreCrypto()
  ml_dsa87.sign = ORIGINAL_ML_DSA_SIGN
  ml_dsa87.verify = ORIGINAL_ML_DSA_VERIFY
  ml_kem1024.encapsulate = ORIGINAL_ML_KEM_ENCAPSULATE
  ml_kem1024.decapsulate = ORIGINAL_ML_KEM_DECAPSULATE

  const internals = await loadDistInternals()
  internals.resetKeyAgreementValidateKeyByAlgCodeForTest()
  internals.resetDigitalSignatureValidateKeyByAlgCodeForTest()
})

test('dist internals expose the default CryptosuiteError message branch', async () => {
  const { CryptosuiteError } = await loadDistInternals()
  const error = new CryptosuiteError('ALGORITHM_UNSUPPORTED')
  assert.equal(
    error.message,
    '{@sovereignbase/cryptosuite} ALGORITHM_UNSUPPORTED'
  )
})

test('dist internals expose getBufferSourceLength array-buffer and invalid-input branches', async () => {
  const { getBufferSourceLength } = await loadDistInternals()
  assert.equal(getBufferSourceLength(new ArrayBuffer(7), 'x'), 7)
  expectCodeSync(
    () => getBufferSourceLength('x', 'boom'),
    'BUFFER_SOURCE_EXPECTED'
  )
})

test('dist cipher helpers cover unsupported and malformed branches', async () => {
  const internals = await loadDistInternals()

  expectCodeSync(
    () => internals.validateCipherKeyByAlgCodeInternal(null),
    'CIPHER_KEY_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateCipherKeyByAlgCodeInternal(
        createA256CtrKey({ use: 'sig' })
      ),
    'CIPHER_KEY_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateCipherKeyByAlgCodeInternal(
        createA256CtrKey({ key_ops: 'encrypt' })
      ),
    'CIPHER_KEY_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateCipherKeyByAlgCodeInternal(
        createA256CtrKey({ k: toBase64UrlString(filledBytes(31, 1)) })
      ),
    'CIPHER_KEY_INVALID'
  )
  expectCodeSync(
    () => internals.getCipherImportKeyAlgorithmByAlgCodeInternal('A128CTR'),
    'ALGORITHM_UNSUPPORTED'
  )
  expectCodeSync(
    () => internals.createCipherParamsByAlgCodeInternal('A128CTR'),
    'ALGORITHM_UNSUPPORTED'
  )
  expectCodeSync(
    () =>
      internals.getCipherParamsByAlgCodeInternal('A256CTR', {
        iv: new ArrayBuffer(12),
      }),
    'CIPHER_MESSAGE_INVALID'
  )
  expectCodeSync(
    () =>
      internals.getCipherParamsByAlgCodeInternal('A128CTR', {
        iv: new Uint8Array(12),
      }),
    'ALGORITHM_UNSUPPORTED'
  )
})

test('dist cipher harness covers subtle-unavailable and decrypt iv-type branches', async () => {
  const { CipherKeyHarness } = await loadDistInternals()

  setCrypto({})
  expectCodeSync(
    () => new CipherKeyHarness(createA256CtrKey()),
    'SUBTLE_UNAVAILABLE'
  )

  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        decrypt: async () => new ArrayBuffer(0),
      },
    })
  )
  const harness = new CipherKeyHarness(createA256CtrKey())
  await expectCodeAsync(
    () =>
      harness.decrypt({
        ciphertext: new ArrayBuffer(1),
        iv: new ArrayBuffer(12),
      }),
    'CIPHER_MESSAGE_INVALID'
  )
})

test('dist message authentication helpers cover unsupported and malformed branches', async () => {
  const internals = await loadDistInternals()

  expectCodeSync(
    () => internals.validateMessageAuthenticationKeyByAlgCodeInternal(null),
    'HMAC_JWK_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateMessageAuthenticationKeyByAlgCodeInternal(
        createHs256Key({ use: 'enc' })
      ),
    'HMAC_JWK_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateMessageAuthenticationKeyByAlgCodeInternal(
        createHs256Key({ key_ops: 'sign' })
      ),
    'HMAC_JWK_INVALID'
  )
  expectCodeSync(
    () =>
      internals.createMessageAuthenticationImportKeyAlgorithmByAlgCodeInternal(
        'HS512'
      ),
    'ALGORITHM_UNSUPPORTED'
  )
  expectCodeSync(
    () => internals.createMessageAuthenticationParamsByAlgCodeInternal('HS512'),
    'ALGORITHM_UNSUPPORTED'
  )
  expectCodeSync(
    () =>
      internals.getMessageAuthenticationParamsByAlgCodeInternal('HS512', {}),
    'ALGORITHM_UNSUPPORTED'
  )
})

test('dist message authentication harness covers subtle-unavailable branch', async () => {
  const { MessageAuthenticationKeyHarness } = await loadDistInternals()
  setCrypto({})
  expectCodeSync(
    () => new MessageAuthenticationKeyHarness(createHs256Key()),
    'SUBTLE_UNAVAILABLE'
  )
})

test('dist key agreement helpers cover unsupported and malformed branches', async () => {
  const internals = await loadDistInternals()

  expectCodeSync(
    () => internals.validateKeyAgreementKeyByAlgCodeInternal(null),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateKeyAgreementKeyByAlgCodeInternal(
        createMlKemPublicKey({ kty: 'oct' })
      ),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateKeyAgreementKeyByAlgCodeInternal(
        createMlKemPublicKey({ use: 'sig' })
      ),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateKeyAgreementKeyByAlgCodeInternal(
        createMlKemPrivateKey({ key_ops: ['encrypt'] })
      ),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateKeyAgreementKeyByAlgCodeInternal(
        createMlKemPrivateKey({
          d: toBase64UrlString(
            filledBytes(ml_kem1024.lengths.secretKey - 1, 4)
          ),
        })
      ),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateKeyAgreementKeyByAlgCodeInternal(
        createMlKemPublicKey({ key_ops: ['deriveKey'] })
      ),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateKeyAgreementKeyByAlgCodeInternal(
        createMlKemPublicKey({
          x: toBase64UrlString(
            filledBytes(ml_kem1024.lengths.publicKey - 1, 3)
          ),
        })
      ),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateKeyAgreementKeyByAlgCodeInternal({
        kty: 'AKP',
        alg: 'ML-KEM-1024',
      }),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateKeyAgreementKeyByAlgCodeInternal(
        createMlKemPublicKey({ alg: 'ML-KEM-768' })
      ),
    'ALGORITHM_UNSUPPORTED'
  )
  expectCodeSync(
    () => internals.createKeyAgreementImportKeyAlgorithmByAlgCodeInternal('X'),
    'ALGORITHM_UNSUPPORTED'
  )
  expectCodeSync(
    () => internals.createKeyAgreementParamsByAlgCodeInternal({}),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () => internals.getKeyAgreementParamsByAlgCodeInternal('X', {}),
    'ALGORITHM_UNSUPPORTED'
  )
})

test('dist key agreement harnesses cover constructor and params invariant branches', async () => {
  const internals = await loadDistInternals()
  const { EncapsulateKeyHarness, DecapsulateKeyHarness } = internals

  setCrypto({})
  expectCodeSync(
    () => new EncapsulateKeyHarness(createMlKemPublicKey()),
    'SUBTLE_UNAVAILABLE'
  )
  expectCodeSync(
    () => new DecapsulateKeyHarness(createMlKemPrivateKey()),
    'SUBTLE_UNAVAILABLE'
  )

  setCrypto(buildCrypto())
  expectCodeSync(
    () => new EncapsulateKeyHarness(createMlKemPrivateKey()),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  expectCodeSync(
    () => new DecapsulateKeyHarness(createMlKemPublicKey()),
    'KEY_AGREEMENT_KEY_INVALID'
  )

  const encapsulator = new EncapsulateKeyHarness(createMlKemPublicKey())
  encapsulator.params = {
    secretKey: filledBytes(ml_kem1024.lengths.secretKey, 9),
  }
  await expectCodeAsync(
    () => encapsulator.encapsulate(),
    'KEY_AGREEMENT_KEY_INVALID'
  )

  const decapsulator = new DecapsulateKeyHarness(createMlKemPrivateKey())
  decapsulator.params = {
    publicKey: filledBytes(ml_kem1024.lengths.publicKey, 9),
  }
  await expectCodeAsync(
    () =>
      decapsulator.decapsulate({
        ciphertext: new ArrayBuffer(ml_kem1024.lengths.cipherText),
      }),
    'KEY_AGREEMENT_KEY_INVALID'
  )
})

test('dist key agreement harnesses cover encapsulation and decapsulation failure catches', async () => {
  const { EncapsulateKeyHarness, DecapsulateKeyHarness } =
    await loadDistInternals()

  setCrypto(
    buildCrypto({
      subtle: {
        importKey: async () => ({}),
        exportKey: async () => createA256CtrKey(),
      },
    })
  )
  ml_kem1024.encapsulate = () => {
    throw new Error('boom')
  }
  await expectCodeAsync(
    () => new EncapsulateKeyHarness(createMlKemPublicKey()).encapsulate(),
    'ENCAPSULATION_FAILED'
  )

  ml_kem1024.encapsulate = ORIGINAL_ML_KEM_ENCAPSULATE
  ml_kem1024.decapsulate = () => {
    throw new Error('boom')
  }
  await expectCodeAsync(
    () =>
      new DecapsulateKeyHarness(createMlKemPrivateKey()).decapsulate({
        ciphertext: new ArrayBuffer(ml_kem1024.lengths.cipherText),
      }),
    'DECAPSULATION_FAILED'
  )
})

test('dist key agreement generate/derive keypair cover internal invariant branches', async () => {
  const internals = await loadDistInternals()
  const originalValidate = internals.validateKeyAgreementKeyByAlgCodeInternal

  internals.setKeyAgreementValidateKeyByAlgCodeForTest((key) => {
    if ('x' in key) return createMlKemPrivateKey()
    return createMlKemPrivateKey()
  })
  await expectCodeAsync(
    () => internals.generateKeyAgreementKeypair(),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  await expectCodeAsync(
    () =>
      internals.deriveKeyAgreementKeypair(
        filledBytes(ml_kem1024.lengths.seed, 1)
      ),
    'KEY_AGREEMENT_KEY_INVALID'
  )

  internals.setKeyAgreementValidateKeyByAlgCodeForTest((key) => {
    if ('x' in key) return createMlKemPublicKey()
    return createMlKemPublicKey()
  })
  await expectCodeAsync(
    () => internals.generateKeyAgreementKeypair(),
    'KEY_AGREEMENT_KEY_INVALID'
  )
  await expectCodeAsync(
    () =>
      internals.deriveKeyAgreementKeypair(
        filledBytes(ml_kem1024.lengths.seed, 2)
      ),
    'KEY_AGREEMENT_KEY_INVALID'
  )

  internals.setKeyAgreementValidateKeyByAlgCodeForTest(originalValidate)
})

test('dist digital signature helpers cover unsupported and malformed branches', async () => {
  const internals = await loadDistInternals()

  expectCodeSync(
    () => internals.validateDigitalSignatureKeyByAlgCodeInternal(null),
    'SIGN_JWK_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateDigitalSignatureKeyByAlgCodeInternal(
        createMlDsaSignKey({ kty: 'oct' })
      ),
    'SIGN_JWK_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateDigitalSignatureKeyByAlgCodeInternal(
        createMlDsaSignKey({ use: 'enc' })
      ),
    'SIGN_JWK_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateDigitalSignatureKeyByAlgCodeInternal(
        createMlDsaSignKey({ key_ops: ['verify'] })
      ),
    'SIGN_JWK_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateDigitalSignatureKeyByAlgCodeInternal(
        createMlDsaSignKey({
          d: toBase64UrlString(filledBytes(ml_dsa87.lengths.secretKey - 1, 5)),
        })
      ),
    'SIGN_JWK_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateDigitalSignatureKeyByAlgCodeInternal(
        createMlDsaVerifyKey({ key_ops: ['sign'] })
      ),
    'VERIFY_JWK_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateDigitalSignatureKeyByAlgCodeInternal(
        createMlDsaVerifyKey({
          x: toBase64UrlString(filledBytes(ml_dsa87.lengths.publicKey - 1, 6)),
        })
      ),
    'VERIFY_JWK_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateDigitalSignatureKeyByAlgCodeInternal({
        kty: 'AKP',
        alg: 'ML-DSA-87',
      }),
    'SIGN_JWK_INVALID'
  )
  expectCodeSync(
    () =>
      internals.validateDigitalSignatureKeyByAlgCodeInternal(
        createMlDsaSignKey({ alg: 'ML-DSA-65' })
      ),
    'ALGORITHM_UNSUPPORTED'
  )
  expectCodeSync(
    () =>
      internals.createDigitalSignatureImportKeyAlgorithmByAlgCodeInternal('X'),
    'ALGORITHM_UNSUPPORTED'
  )
  expectCodeSync(
    () => internals.createDigitalSignatureParamsByAlgCodeInternal({}),
    'SIGN_JWK_INVALID'
  )
  expectCodeSync(
    () => internals.getDigitalSignatureParamsByAlgCodeInternal('X', {}),
    'ALGORITHM_UNSUPPORTED'
  )
})

test('dist digital signature harnesses cover constructor and params invariant branches', async () => {
  const internals = await loadDistInternals()
  const { SignKeyHarness, VerifyKeyHarness } = internals

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
})

test('dist digital signature harnesses cover sign and verify failure catches', async () => {
  const internals = await loadDistInternals()
  const { SignKeyHarness, VerifyKeyHarness } = internals

  ml_dsa87.sign = () => {
    throw new Error('boom')
  }
  await expectCodeAsync(
    () => new SignKeyHarness(createMlDsaSignKey()).sign(bytes(1, 2, 3)),
    'ALGORITHM_UNSUPPORTED'
  )

  ml_dsa87.sign = ORIGINAL_ML_DSA_SIGN
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

test('dist digital signature generate/derive keypair cover internal invariant branches', async () => {
  const internals = await loadDistInternals()
  const originalValidate =
    internals.validateDigitalSignatureKeyByAlgCodeInternal

  internals.setDigitalSignatureValidateKeyByAlgCodeForTest((key) => {
    if ('d' in key) return createMlDsaVerifyKey()
    return createMlDsaVerifyKey()
  })
  await expectCodeAsync(
    () => internals.generateDigitalSignatureKeypair(),
    'SIGN_JWK_INVALID'
  )
  await expectCodeAsync(
    () => internals.deriveDigitalSignatureKeypair(filledBytes(32, 1)),
    'SIGN_JWK_INVALID'
  )

  internals.setDigitalSignatureValidateKeyByAlgCodeForTest((key) => {
    if ('d' in key) return createMlDsaSignKey()
    return createMlDsaSignKey()
  })
  await expectCodeAsync(
    () => internals.generateDigitalSignatureKeypair(),
    'VERIFY_JWK_INVALID'
  )
  await expectCodeAsync(
    () => internals.deriveDigitalSignatureKeypair(filledBytes(32, 2)),
    'VERIFY_JWK_INVALID'
  )

  internals.setDigitalSignatureValidateKeyByAlgCodeForTest(originalValidate)
})
