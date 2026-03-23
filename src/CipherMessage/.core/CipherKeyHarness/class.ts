import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../../.errors/class.js'
import type { CipherKey, CipherMessage, CipherParams } from '../types/index.js'
import { validateKeyByAlgCode } from '../helpers/validateKeyByAlgCode/index.js'
import { createParamsByAlgCode } from '../helpers/createParamsByAlgCode/index.js'
import { getParamsByAlgCode } from '../helpers/getParamsByAlgCode/index.js'
import { getImportKeyAlgorithmByAlgCode } from '../helpers/getImportKeyAlgorithmByAlgCode/index.js'

export class CipherKeyHarness {
  private readonly algCode: CipherKey['alg']
  private readonly keyPromise: Promise<CryptoKey>

  constructor(cipherKey: CipherKey) {
    const validated = validateKeyByAlgCode(cipherKey)
    const algCode = validated.alg
    this.algCode = algCode

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
          validated,
          getImportKeyAlgorithmByAlgCode(algCode),
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
    const params = createParamsByAlgCode(this.algCode)
    return {
      ...params,
      ciphertext: await crypto.subtle.encrypt(
        getParamsByAlgCode(this.algCode, params),
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

    const params: CipherParams = {
      iv: cipherMessage.iv,
    }
    const plaintext = await crypto.subtle.decrypt(
      getParamsByAlgCode(this.algCode, params),
      key,
      cipherMessage.ciphertext
    )
    return new Uint8Array(plaintext)
  }
}
