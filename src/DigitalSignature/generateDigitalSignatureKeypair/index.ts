import { toBase64UrlString } from '@sovereignbase/bytecodec'
import { createImportKeyAlgorithmByAlgCode } from '../.core/helpers/createImportKeyAlgorithmByAlgCode/index.js'
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
  const { publicKey, secretKey } =
    createImportKeyAlgorithmByAlgCode('Ed25519-ML-DSA-65').keygen()
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
