import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../../.errors/class.js'
import { validateKeyByAlgCode } from '../helpers/validateKeyByAlgCode/index.js'
import { createImportKeyAlgorithmByAlgCode } from '../helpers/createImportKeyAlgorithmByAlgCode/index.js'
import { createParamsByAlgCode } from '../helpers/createParamsByAlgCode/index.js'
import { getParamsByAlgCode } from '../helpers/getParamsByAlgCode/index.js'
import type {
  MessageAuthenticationKey,
  MessageAuthenticationParams,
} from '../types/index.js'

export class MessageAuthenticationKeyHarness {
  private readonly algCode: MessageAuthenticationKey['alg']
  private readonly keyPromise: Promise<CryptoKey>

  constructor(messageAuthenticationKey: MessageAuthenticationKey) {
    const validated = validateKeyByAlgCode(messageAuthenticationKey)
    const algCode = validated.alg
    this.algCode = algCode

    if (!globalThis.crypto?.subtle) {
      throw new CryptosuiteError(
        'SUBTLE_UNAVAILABLE',
        'MessageAuthenticationKeyHarness: crypto.subtle is unavailable.'
      )
    }

    this.keyPromise = (async () => {
      try {
        return await crypto.subtle.importKey(
          'jwk',
          validated,
          createImportKeyAlgorithmByAlgCode(algCode),
          false,
          ['sign', 'verify']
        )
      } catch {
        throw new CryptosuiteError(
          'ALGORITHM_UNSUPPORTED',
          'MessageAuthenticationKeyHarness: message authentication key is not supported by this WebCrypto runtime.'
        )
      }
    })()
  }

  async sign(bytes: Uint8Array): Promise<ArrayBuffer> {
    const key = await this.keyPromise
    const params: MessageAuthenticationParams = createParamsByAlgCode(
      this.algCode
    )
    return await crypto.subtle.sign(
      getParamsByAlgCode(this.algCode, params),
      key,
      toBufferSource(bytes)
    )
  }

  async verify(bytes: Uint8Array, signature: ArrayBuffer): Promise<boolean> {
    const key = await this.keyPromise
    const params: MessageAuthenticationParams = createParamsByAlgCode(
      this.algCode
    )
    return await crypto.subtle.verify(
      getParamsByAlgCode(this.algCode, params),
      key,
      signature,
      toBufferSource(bytes)
    )
  }
}
