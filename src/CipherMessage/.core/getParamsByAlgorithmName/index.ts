import { CryptosuiteError } from '../../../.errors/class.js'
import type {
  A256CTRParams,
  CipherAlgorithmName,
  CipherMessage,
  CipherParams,
} from '../types/index.js'

type CipherAlgorithmRuntime = {
  importKeyAlgorithm: AlgorithmIdentifier
  createParams: () => CipherParams
  pickParams: (cipherMessage: CipherMessage) => CipherParams
  toWebCryptoParams: (params: CipherParams) => AlgorithmIdentifier
}

export function getParamsByAlgorithmName(
  algorithmName: CipherAlgorithmName
): CipherAlgorithmRuntime {
  switch (algorithmName) {
    case 'AES-CTR':
      return {
        importKeyAlgorithm: {
          name: 'AES-CTR',
        },
        createParams(): A256CTRParams {
          if (!globalThis.crypto?.getRandomValues) {
            throw new CryptosuiteError(
              'GET_RANDOM_VALUES_UNAVAILABLE',
              'getParamsByAlgorithmName: crypto.getRandomValues is unavailable.'
            )
          }

          return {
            iv: crypto.getRandomValues(new Uint8Array(12)),
          }
        },
        pickParams(cipherMessage): A256CTRParams {
          if (!(cipherMessage.iv instanceof Uint8Array)) {
            throw new CryptosuiteError(
              'CIPHER_MESSAGE_INVALID',
              'getParamsByAlgorithmName: expected a Uint8Array iv for AES-CTR.'
            )
          }

          return {
            iv: cipherMessage.iv,
          }
        },
        toWebCryptoParams(params): AesCtrParams {
          const { iv } = params as A256CTRParams
          if (iv.byteLength !== 12) {
            throw new CryptosuiteError(
              'CIPHER_MESSAGE_INVALID',
              'getParamsByAlgorithmName: expected a 96-bit IV for AES-CTR.'
            )
          }

          const counter = new Uint8Array(16)
          counter.set(iv)
          return {
            name: 'AES-CTR',
            counter,
            length: 32,
          }
        },
      }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `getParamsByAlgorithmName: unsupported WebCrypto algorithm "${algorithmName}".`
  )
}
