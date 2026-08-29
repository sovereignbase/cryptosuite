import { toBase64UrlString } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { getBufferSourceLength } from '../../.helpers/getBufferSourceLength.js'
import { createImportKeyAlgorithmByAlgCode } from '../.core/helpers/createImportKeyAlgorithmByAlgCode/index.js'
import { validateKeyByAlgCode } from '../.core/helpers/validateKeyByAlgCode/index.js'
import type { SignKey, VerifyKey } from '../.core/types/index.js'

/**
 * Deterministically derives a digital signature key pair from source key material.
 *
 * @param sourceKeyMaterial - The source bytes to derive from.
 * @returns The derived private signing key and public verification key.
 */
export async function deriveDigitalSignatureKeypair(
  sourceKeyMaterial: Uint8Array
): Promise<{
  signKey: SignKey
  verifyKey: VerifyKey
}> {
  const algorithm = createImportKeyAlgorithmByAlgCode('Ed25519-ML-DSA-65')
  if (
    getBufferSourceLength(
      sourceKeyMaterial,
      'deriveDigitalSignatureKeypair'
    ) !== algorithm.lengths.seed
  ) {
    throw new CryptosuiteError(
      'SIGN_JWK_INVALID',
      `deriveDigitalSignatureKeypair: source key material must be exactly ${algorithm.lengths.seed} bytes.`
    )
  }

  const { publicKey, secretKey } = algorithm.keygen(sourceKeyMaterial)
  const signKey = validateKeyByAlgCode({
    kty: 'AKP',
    alg: 'Ed25519-ML-DSA-65',
    d: toBase64UrlString(secretKey),
    use: 'sig',
    key_ops: ['sign'],
  })
  const verifyKey = validateKeyByAlgCode({
    kty: 'AKP',
    alg: 'Ed25519-ML-DSA-65',
    x: toBase64UrlString(publicKey),
    use: 'sig',
    key_ops: ['verify'],
  })

  return {
    signKey: signKey as SignKey,
    verifyKey: verifyKey as VerifyKey,
  }
}
