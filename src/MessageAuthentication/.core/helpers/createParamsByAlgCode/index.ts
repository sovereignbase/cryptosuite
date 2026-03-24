import { CryptosuiteError } from '../../../../.errors/class.js'
import type {
  MessageAuthenticationKey,
  MessageAuthenticationParams,
} from '../../types/index.js'

export function createParamsByAlgCode(
  algCode: MessageAuthenticationKey['alg']
): MessageAuthenticationParams {
  switch (algCode) {
    case 'HS256':
      return {}
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `createParamsByAlgCode: unsupported message authentication JWK alg "${algCode}"; expected HS256.`
  )
}
