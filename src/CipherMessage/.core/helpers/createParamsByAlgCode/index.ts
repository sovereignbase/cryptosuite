import { CryptosuiteError } from '../../../../.errors/class.js'
import type { CipherKey, CipherParams } from '../../types/index.js'

export function createParamsByAlgCode(algCode: CipherKey['alg']): CipherParams {
  switch (algCode) {
    case 'A256CTR':
      if (!globalThis.crypto?.getRandomValues) {
        throw new CryptosuiteError(
          'GET_RANDOM_VALUES_UNAVAILABLE',
          'createParamsByAlgCode: crypto.getRandomValues is unavailable.'
        )
      }

      return {
        iv: crypto.getRandomValues(new Uint8Array(12)),
      }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `createParamsByAlgCode: unsupported cipher JWK alg "${algCode}".`
  )
}
