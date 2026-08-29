import { CryptosuiteError } from '../../../../.errors/class.js'
import type {
  DigitalSignatureParams,
  SignKey,
  VerifyKey,
} from '../../types/index.js'

export function getParamsByAlgCode(
  algCode: SignKey['alg'] | VerifyKey['alg'],
  params: DigitalSignatureParams
): DigitalSignatureParams {
  switch (algCode) {
    case 'ML-DSA-87':
    case 'Ed25519-ML-DSA-65':
      return params
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `getParamsByAlgCode: unsupported digital signature alg "${algCode}".`
  )
}
