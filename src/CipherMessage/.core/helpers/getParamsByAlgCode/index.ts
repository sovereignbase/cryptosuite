import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../../../.errors/class.js'
import { normalizeBytes } from '../../../../.helpers/normalizeBytes.js'
import type {
  CipherKey,
  CipherParams,
  A256CTRParams,
  A256GCMParams,
} from '../../types/index.js'

export function getParamsByAlgCode(
  algCode: CipherKey['alg'],
  params: CipherParams
): AesCtrParams | AesGcmParams {
  switch (algCode) {
    case 'A256CTR': {
      const { iv } = params as A256CTRParams
      const normalizedIv = normalizeBytes(
        iv,
        'getParamsByAlgCode AES-CTR iv',
        'CIPHER_MESSAGE_INVALID'
      )

      if (normalizedIv.byteLength !== 12) {
        throw new CryptosuiteError(
          'CIPHER_MESSAGE_INVALID',
          'getParamsByAlgCode: expected a 96-bit IV for AES-CTR.'
        )
      }

      const counter = new Uint8Array(16)
      counter.set(normalizedIv)
      return {
        name: 'AES-CTR',
        counter,
        length: 32,
      }
    }
    case 'A256GCM': {
      const { iv } = params as A256GCMParams
      const normalizedIv = normalizeBytes(
        iv,
        'getParamsByAlgCode AES-GCM iv',
        'CIPHER_MESSAGE_INVALID'
      )

      if (normalizedIv.byteLength !== 12) {
        throw new CryptosuiteError(
          'CIPHER_MESSAGE_INVALID',
          'getParamsByAlgCode: expected a 96-bit IV for AES-GCM.'
        )
      }

      return {
        name: 'AES-GCM',
        iv: toBufferSource(normalizedIv),
        tagLength: 128,
      }
    }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `getParamsByAlgCode: unsupported cipher JWK alg "${algCode}".`
  )
}
