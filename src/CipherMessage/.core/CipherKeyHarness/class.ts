import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../../.errors/class.js'
import {
  getAlgorithmNameFromKey,
  validateKeyByAlgorithmName,
} from '../validateKeyByAlgorihtmName/index.js'
import type { CipherKey, CipherMessage } from '../types/index.js'
import { getParamsByAlgorithmName } from '../getParamsByAlgorithmName/index.js'

export class CipherKeyHarness {
  private readonly keyPromise: Promise<CryptoKey>
  private readonly runtime: ReturnType<typeof getParamsByAlgorithmName>

  constructor(cipherKey: CipherKey) {
    const normalized = validateKeyByAlgorithmName(cipherKey)
    const runtime = getParamsByAlgorithmName(
      getAlgorithmNameFromKey(normalized)
    )
    this.runtime = runtime

    if (!globalThis.crypto?.subtle) {
      throw new CryptosuiteError(
        'SUBTLE_UNAVAILABLE',
        'CipherKeyHarness: crypto.subtle is unavailable.'
      )
    }

    this.keyPromise = (async () => {
      try {
        return await crypto.subtle.importKey(
          'jwk',
          normalized,
          runtime.importKeyAlgorithm,
          false,
          ['encrypt', 'decrypt']
        )
      } catch {
        throw new CryptosuiteError(
          'ALGORITHM_UNSUPPORTED',
          'CipherKeyHarness: cipher key is not supported by this WebCrypto runtime.'
        )
      }
    })()
  }

  async encrypt(messageBytes: Uint8Array): Promise<CipherMessage> {
    const key = await this.keyPromise
    const params = this.runtime.createParams()
    return {
      ...params,
      ciphertext: await crypto.subtle.encrypt(
        this.runtime.toWebCryptoParams(params),
        key,
        toBufferSource(messageBytes)
      ),
    }
  }

  async decrypt(cipherMessage: CipherMessage): Promise<Uint8Array> {
    const key = await this.keyPromise
    if (
      !cipherMessage ||
      typeof cipherMessage !== 'object' ||
      !(cipherMessage.ciphertext instanceof ArrayBuffer)
    ) {
      throw new CryptosuiteError(
        'CIPHER_MESSAGE_INVALID',
        'CipherKeyHarness.decrypt: expected a cipher message with ciphertext.'
      )
    }

    const params = this.runtime.pickParams(cipherMessage)
    const plaintext = await crypto.subtle.decrypt(
      this.runtime.toWebCryptoParams(params),
      key,
      cipherMessage.ciphertext
    )
    return new Uint8Array(plaintext)
  }
}
