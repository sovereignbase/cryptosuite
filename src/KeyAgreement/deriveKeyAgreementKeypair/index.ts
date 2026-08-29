import { toBase64UrlString } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { getBufferSourceLength } from '../../.helpers/getBufferSourceLength.js'
import { createImportKeyAlgorithmByAlgCode } from '../.core/helpers/createImportKeyAlgorithmByAlgCode/index.js'
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
  const algorithm = createImportKeyAlgorithmByAlgCode('X25519-ML-KEM-768')
  if (
    getBufferSourceLength(sourceKeyMaterial, 'deriveKeyAgreementKeypair') !==
    algorithm.lengths.seed
  ) {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_KEY_INVALID',
      `deriveKeyAgreementKeypair: source key material must be exactly ${algorithm.lengths.seed} bytes.`
    )
  }

  const { publicKey, secretKey } = algorithm.keygen(sourceKeyMaterial)
  const encapsulateKey = validateKeyByAlgCode({
    kty: 'AKP',
    alg: 'X25519-ML-KEM-768',
    x: toBase64UrlString(publicKey),
    use: 'enc',
    key_ops: [],
  })
  const decapsulateKey = validateKeyByAlgCode({
    kty: 'AKP',
    alg: 'X25519-ML-KEM-768',
    d: toBase64UrlString(secretKey),
    use: 'enc',
    key_ops: ['deriveKey', 'deriveBits'],
  })

  return {
    encapsulateKey: encapsulateKey as EncapsulateKey,
    decapsulateKey: decapsulateKey as DecapsulateKey,
  }
}
