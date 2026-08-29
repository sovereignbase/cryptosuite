import { toBufferSource, toUint8Array } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../../.errors/class.js'
import { normalizeBytes } from '../../../.helpers/normalizeBytes.js'
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
    const plaintext = normalizeBytes(
      messageBytes,
      'CipherKeyHarness.encrypt messageBytes'
    )
    return {
      ...params,
      ciphertext: toUint8Array(
        await crypto.subtle.encrypt(
          getParamsByAlgCode(this.algCode, params),
          key,
          toBufferSource(plaintext)
        )
      ),
    }
  }

  async decrypt(cipherMessage: CipherMessage): Promise<Uint8Array> {
    const key = await this.keyPromise
    if (!cipherMessage || typeof cipherMessage !== 'object') {
      throw new CryptosuiteError(
        'CIPHER_MESSAGE_INVALID',
        'CipherKeyHarness.decrypt: expected a cipher message with ciphertext.'
      )
    }

    const ciphertext = normalizeBytes(
      cipherMessage.ciphertext,
      'CipherKeyHarness.decrypt ciphertext',
      'CIPHER_MESSAGE_INVALID'
    )

    const params: CipherParams = {
      iv: cipherMessage.iv,
    }
    let plaintext: Uint8Array
    try {
      plaintext = toUint8Array(
        await crypto.subtle.decrypt(
          getParamsByAlgCode(this.algCode, params),
          key,
          toBufferSource(ciphertext)
        )
      )
    } catch (error) {
      if (error instanceof CryptosuiteError) throw error
      throw new CryptosuiteError(
        'CIPHER_ARTIFACT_INVALID',
        'CipherKeyHarness.decrypt: failed to decrypt or authenticate the cipher message.'
      )
    }
    return plaintext
  }
}
