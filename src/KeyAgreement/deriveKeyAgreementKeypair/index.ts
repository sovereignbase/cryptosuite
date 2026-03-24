import { toBase64UrlString } from '@sovereignbase/bytecodec'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { CryptosuiteError } from '../../.errors/class.js'
import { getBufferSourceLength } from '../../.helpers/getBufferSourceLength.js'
import { validateKeyByAlgCode } from '../.core/helpers/validateKeyByAlgCode/index.js'
import type { DecapsulateKey } from '../.core/types/index.js'
import type { EncapsulateKey } from '../.core/types/index.js'

/**
 * Deterministically derives a key agreement key pair from source key material.
 *
 * @param sourceKeyMaterial - The source bytes to derive from.
 * @returns The derived public and private key agreement keys.
 */
export async function deriveKeyAgreementKeypair(
  sourceKeyMaterial: Uint8Array
): Promise<{
  encapsulateKey: EncapsulateKey
  decapsulateKey: DecapsulateKey
}> {
  if (
    getBufferSourceLength(sourceKeyMaterial, 'deriveKeyAgreementKeypair') !==
    ml_kem1024.lengths.seed
  ) {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_KEY_INVALID',
      `deriveKeyAgreementKeypair: source key material must be exactly ${ml_kem1024.lengths.seed} bytes.`
    )
  }

  const { publicKey, secretKey } = ml_kem1024.keygen(sourceKeyMaterial)
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
      'deriveKeyAgreementKeypair: internal key validation invariant failed.'
    )
  }

  if (!('d' in decapsulateKey)) {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_KEY_INVALID',
      'deriveKeyAgreementKeypair: internal key validation invariant failed.'
    )
  }

  const normalizedEncapsulateKey = encapsulateKey as EncapsulateKey
  const normalizedDecapsulateKey = decapsulateKey as DecapsulateKey

  return {
    encapsulateKey: normalizedEncapsulateKey,
    decapsulateKey: normalizedDecapsulateKey,
  }
}
