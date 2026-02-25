import { toBufferSource } from '@z-base/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import type { SignJWK } from '../types/index.js'
import { normalizeSignJWK } from '../normalizeSignJWK/index.js'

export class SignKeyHarness {
  private keyPromise: Promise<CryptoKey>
  private keyAlgorithm: string = ''

  constructor(signJwk: SignJWK) {
    assertSubtleAvailable('VerifyKeyHarness')

    const normalized = normalizeSignJWK(signJwk)
    this.keyAlgorithm = normalized.alg

    this.keyPromise = (async () => {
      try {
        return await crypto.subtle.importKey(
          'jwk',
          normalized,
          { name: this.keyAlgorithm },
          false,
          ['sign']
        )
      } catch {
        throw new CryptosuiteError(
          'SIGN_KEY_IMPORT_FAILED',
          'SignKeyHarness: sign key is not supported by this WebCrypto runtime.'
        )
      }
    })()
  }

  async sign(bytes: Uint8Array): Promise<ArrayBuffer> {
    const key = await this.keyPromise
    return crypto.subtle.sign(this.keyAlgorithm, key, toBufferSource(bytes))
  }
}
