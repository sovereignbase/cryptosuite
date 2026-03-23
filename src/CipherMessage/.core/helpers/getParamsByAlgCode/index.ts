import { CryptosuiteError } from '../../../../.errors/class.js'
import type {
  CipherKey,
  CipherParams,
  A256CTRParams,
} from '../../types/index.js'

export function getParamsByAlgCode(
  algCode: CipherKey['alg'],
  params: CipherParams
): AesCtrParams {
  switch (algCode) {
    case 'A256CTR': {
      const { iv } = params as A256CTRParams

      if (!(iv instanceof Uint8Array)) {
        throw new CryptosuiteError(
          'CIPHER_MESSAGE_INVALID',
          'getParamsByAlgCode: expected a Uint8Array iv for AES-CTR.'
        )
      }

      if (iv.byteLength !== 12) {
        throw new CryptosuiteError(
          'CIPHER_MESSAGE_INVALID',
          'getParamsByAlgCode: expected a 96-bit IV for AES-CTR.'
        )
      }

      const counter = new Uint8Array(16)
      counter.set(iv)
      return {
        name: 'AES-CTR',
        counter,
        length: 32,
      }
    }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `getParamsByAlgCode: unsupported cipher JWK alg "${algCode}".`
  )
}
