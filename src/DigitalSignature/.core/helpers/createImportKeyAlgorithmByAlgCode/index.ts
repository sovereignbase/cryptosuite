import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { CryptosuiteError } from '../../../../.errors/class.js'
import type { SignKey, VerifyKey } from '../../types/index.js'

export function createImportKeyAlgorithmByAlgCode(
  algCode: SignKey['alg'] | VerifyKey['alg']
): typeof ml_dsa87 {
  switch (algCode) {
    case 'ML-DSA-87':
      return ml_dsa87
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `createImportKeyAlgorithmByAlgCode: unsupported digital signature alg "${algCode}".`
  )
}
