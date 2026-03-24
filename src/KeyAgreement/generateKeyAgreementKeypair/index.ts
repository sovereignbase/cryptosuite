import { toBase64UrlString } from '@sovereignbase/bytecodec'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { CryptosuiteError } from '../../.errors/class.js'
import { validateKeyByAlgCode } from '../.core/helpers/validateKeyByAlgCode/index.js'
import type { EncapsulateKey, DecapsulateKey } from '../.core/types/index.js'

/**
 * Generates a new key agreement key pair.
 *
 * @returns The generated public and private key agreement keys.
 */
export async function generateKeyAgreementKeypair(): Promise<{
  encapsulateKey: EncapsulateKey
  decapsulateKey: DecapsulateKey
}> {
  const { publicKey, secretKey } = ml_kem1024.keygen()
  const encapsulateKey = validateKeyByAlgCode({
    kty: 'AKP',
    alg: 'ML-KEM-1024',
    x: toBase64UrlString(publicKey),
    use: 'enc',
    key_ops: [],
  })
  const decapsulateKey = validateKeyByAlgCode({
    kty: 'AKP',
    alg: 'ML-KEM-1024',
    d: toBase64UrlString(secretKey),
    use: 'enc',
    key_ops: ['deriveKey', 'deriveBits'],
  })

  if (!('x' in encapsulateKey)) {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_KEY_INVALID',
      'generateKeyAgreementKeypair: internal key validation invariant failed.'
    )
  }

  if (!('d' in decapsulateKey)) {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_KEY_INVALID',
      'generateKeyAgreementKeypair: internal key validation invariant failed.'
    )
  }

  const normalizedEncapsulateKey = encapsulateKey as EncapsulateKey
  const normalizedDecapsulateKey = decapsulateKey as DecapsulateKey

  return {
    encapsulateKey: normalizedEncapsulateKey,
    decapsulateKey: normalizedDecapsulateKey,
  }
}
