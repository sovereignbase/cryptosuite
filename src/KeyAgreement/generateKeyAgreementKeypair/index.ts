import { Bytes } from '@sovereignbase/bytecodec'
import { createImportKeyAlgorithmByAlgCode } from '../.core/helpers/createImportKeyAlgorithmByAlgCode/index.js'
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
  const { publicKey, secretKey } =
    createImportKeyAlgorithmByAlgCode('X25519-ML-KEM-768').keygen()
  const encapsulateKey = validateKeyByAlgCode({
    kty: 'AKP',
    alg: 'X25519-ML-KEM-768',
    x: Bytes.base64url.encode(publicKey),
    use: 'enc',
    key_ops: [],
  })
  const decapsulateKey = validateKeyByAlgCode({
    kty: 'AKP',
    alg: 'X25519-ML-KEM-768',
    d: Bytes.base64url.encode(secretKey),
    use: 'enc',
    key_ops: ['deriveKey', 'deriveBits'],
  })

  return {
    encapsulateKey: encapsulateKey as EncapsulateKey,
    decapsulateKey: decapsulateKey as DecapsulateKey,
  }
}
