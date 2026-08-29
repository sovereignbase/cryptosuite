import { CryptosuiteError } from '../../../../.errors/class.js'
import type {
  DecapsulateKey,
  EncapsulateKey,
  KeyAgreementParams,
} from '../../types/index.js'

export function getParamsByAlgCode(
  algCode: EncapsulateKey['alg'] | DecapsulateKey['alg'],
  params: KeyAgreementParams
): KeyAgreementParams {
  switch (algCode) {
    case 'ML-KEM-1024':
    case 'X25519-ML-KEM-768':
      return params
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `getParamsByAlgCode: unsupported key agreement alg "${algCode}".`
  )
}
