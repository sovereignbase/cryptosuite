import { CryptosuiteError } from '../../../../.errors/class.js'
import type { MessageAuthenticationKey } from '../../types/index.js'

export function createImportKeyAlgorithmByAlgCode(
  algCode: MessageAuthenticationKey['alg']
): HmacImportParams {
  switch (algCode) {
    case 'HS256':
      return {
        name: 'HMAC',
        hash: 'SHA-256',
      }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `createImportKeyAlgorithmByAlgCode: unsupported message authentication JWK alg "${algCode}"; expected HS256.`
  )
}
