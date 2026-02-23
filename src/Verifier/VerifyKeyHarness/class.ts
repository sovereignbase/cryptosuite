import { toBufferSource } from '@z-base/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import { normalizeVerifyJWK } from '../normalizeVerifyJWK/index.js'
import type { VerifyJWK } from '../types/index.js'

export class VerifyKeyHarness {
  private keyPromise: Promise<CryptoKey>
  private keyAlgorithm: string = ''
  constructor(verifyJwk: VerifyJWK) {
    assertSubtleAvailable('VerifyKeyHarness')

    const normalized = normalizeVerifyJWK(verifyJwk)
    this.keyAlgorithm = normalized.alg

    this.keyPromise = (async () => {
      try {
        return await crypto.subtle.importKey(
          'jwk',
          normalized,
          { name: this.keyAlgorithm },
          false,
          ['verify']
        )
      } catch {
        throw new CryptosuiteError(
          'VERIFY_KEY_IMPORT_FAILED',
          'VerifyKeyHarness: verify key is not supported by this WebCrypto runtime.'
        )
      }
    })()
  }

  async verify(bytes: Uint8Array, signature: ArrayBuffer): Promise<boolean> {
    const key = await this.keyPromise
    return crypto.subtle.verify(
      this.keyAlgorithm,
      key,
      signature,
      toBufferSource(bytes)
    )
  }
}
