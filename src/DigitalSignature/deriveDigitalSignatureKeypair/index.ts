import { toBase64UrlString } from '@sovereignbase/bytecodec'
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { CryptosuiteError } from '../../.errors/class.js'
import { getBufferSourceLength } from '../../.helpers/getBufferSourceLength.js'
import { validateKeyByAlgCode } from '../.core/helpers/validateKeyByAlgCode/index.js'
import type { SignKey, VerifyKey } from '../.core/types/index.js'

export async function deriveDigitalSignatureKeypair(
  sourceKeyMaterial: Uint8Array
): Promise<{
  signKey: SignKey
  verifyKey: VerifyKey
}> {
  if (
    getBufferSourceLength(
      sourceKeyMaterial,
      'deriveDigitalSignatureKeypair'
    ) !== ml_dsa87.lengths.seed
  ) {
    throw new CryptosuiteError(
      'SIGN_JWK_INVALID',
      `deriveDigitalSignatureKeypair: source key material must be exactly ${ml_dsa87.lengths.seed} bytes.`
    )
  }

  const { publicKey, secretKey } = ml_dsa87.keygen(sourceKeyMaterial)
  const signKey = validateKeyByAlgCode({
    kty: 'AKP',
    alg: 'ML-DSA-87',
    d: toBase64UrlString(secretKey),
    use: 'sig',
    key_ops: ['sign'],
  })
  const verifyKey = validateKeyByAlgCode({
    kty: 'AKP',
    alg: 'ML-DSA-87',
    x: toBase64UrlString(publicKey),
    use: 'sig',
    key_ops: ['verify'],
  })

  if (!('d' in signKey)) {
    throw new CryptosuiteError(
      'SIGN_JWK_INVALID',
      'deriveDigitalSignatureKeypair: internal sign key invariant failed.'
    )
  }

  if (!('x' in verifyKey)) {
    throw new CryptosuiteError(
      'VERIFY_JWK_INVALID',
      'deriveDigitalSignatureKeypair: internal verify key invariant failed.'
    )
  }

  return {
    signKey: signKey as SignKey,
    verifyKey: verifyKey as VerifyKey,
  }
}
