import { ed25519 } from '@noble/curves/ed25519.js'
import { combineSigners, ecSigner } from '@noble/post-quantum/hybrid.js'
import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import type { Signer } from '@noble/post-quantum/utils.js'
import { CryptosuiteError } from '../../../../.errors/class.js'
import type { SignKey, VerifyKey } from '../../types/index.js'

const ed25519MlDsa65 = combineSigners(
  undefined,
  (seed: Uint8Array) => seed,
  ecSigner(ed25519),
  ml_dsa65
)

export function createImportKeyAlgorithmByAlgCode(
  algCode: SignKey['alg'] | VerifyKey['alg']
): typeof ml_dsa87 | Signer {
  switch (algCode) {
    case 'ML-DSA-87':
      return ml_dsa87
    case 'Ed25519-ML-DSA-65':
      return ed25519MlDsa65
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `createImportKeyAlgorithmByAlgCode: unsupported digital signature alg "${algCode}".`
  )
}
