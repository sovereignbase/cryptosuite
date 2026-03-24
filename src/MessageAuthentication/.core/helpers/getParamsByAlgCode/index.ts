import { CryptosuiteError } from '../../../../.errors/class.js'
import type {
  MessageAuthenticationKey,
  MessageAuthenticationParams,
} from '../../types/index.js'

export function getParamsByAlgCode(
  algCode: MessageAuthenticationKey['alg'],
  _params: MessageAuthenticationParams
): AlgorithmIdentifier {
  switch (algCode) {
    case 'HS256':
      return 'HMAC'
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `getParamsByAlgCode: unsupported message authentication JWK alg "${algCode}"; expected HS256.`
  )
}
