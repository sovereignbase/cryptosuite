import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import type { KEM } from '@noble/post-quantum/utils.js'
import { CryptosuiteError } from '../../../../.errors/class.js'
import type { DecapsulateKey, EncapsulateKey } from '../../types/index.js'

export function createImportKeyAlgorithmByAlgCode(
  algCode: EncapsulateKey['alg'] | DecapsulateKey['alg']
): typeof ml_kem1024 | KEM {
  switch (algCode) {
    case 'ML-KEM-1024':
      return ml_kem1024
    case 'X25519-ML-KEM-768':
      return ml_kem768_x25519
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `createImportKeyAlgorithmByAlgCode: unsupported key agreement alg "${algCode}".`
  )
}
