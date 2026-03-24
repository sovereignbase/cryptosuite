import { toBase64UrlString } from '@sovereignbase/bytecodec'
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { CryptosuiteError } from '../../.errors/class.js'
import { validateKeyByAlgCode } from '../.core/helpers/validateKeyByAlgCode/index.js'
import type { SignKey, VerifyKey } from '../.core/types/index.js'

/**
 * Generates a new digital signature key pair.
 *
 * @returns The generated private signing key and public verification key.
 */
export async function generateDigitalSignatureKeypair(): Promise<{
  signKey: SignKey
  verifyKey: VerifyKey
}> {
  const { publicKey, secretKey } = ml_dsa87.keygen()
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

  /* c8 ignore next 6 */
  if (!('d' in signKey)) {
    throw new CryptosuiteError(
      'SIGN_JWK_INVALID',
      'generateDigitalSignatureKeypair: internal sign key invariant failed.'
    )
  }

  /* c8 ignore next 6 */
  if (!('x' in verifyKey)) {
    throw new CryptosuiteError(
      'VERIFY_JWK_INVALID',
      'generateDigitalSignatureKeypair: internal verify key invariant failed.'
    )
  }

  return {
    signKey: signKey as SignKey,
    verifyKey: verifyKey as VerifyKey,
  }
}
