import { CryptosuiteError } from '../../../../.errors/class.js'
import type { CipherKey } from '../../types/index.js'
export function getImportKeyAlgorithmByAlgCode(
  algCode: CipherKey['alg']
): AlgorithmIdentifier {
  switch (algCode) {
    case 'A256CTR':
      return {
        name: 'AES-CTR',
      }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `getImportKeyAlgorithmByAlgCode: unsupported cipher JWK alg "${algCode}".`
  )
}
