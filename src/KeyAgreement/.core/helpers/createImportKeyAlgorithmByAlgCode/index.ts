import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { CryptosuiteError } from '../../../../.errors/class.js'
import type { DecapsulateKey, EncapsulateKey } from '../../types/index.js'

export function createImportKeyAlgorithmByAlgCode(
  algCode: EncapsulateKey['alg'] | DecapsulateKey['alg']
): typeof ml_kem1024 {
  switch (algCode) {
    case 'ML-KEM-1024':
      return ml_kem1024
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `createImportKeyAlgorithmByAlgCode: unsupported key agreement alg "${algCode}".`
  )
}
