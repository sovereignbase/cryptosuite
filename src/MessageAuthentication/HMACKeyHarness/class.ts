import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import { normalizeHMACJWK } from '../normalizeHMACJWK/index.js'
import type { HMACJWK } from '../types/index.js'

export class HMACKeyHarness {
  private readonly keyPromise: Promise<CryptoKey>
  private readonly normalized: HMACJWK

  constructor(hmacJwk: HMACJWK) {
    this.normalized = normalizeHMACJWK(hmacJwk)
    assertSubtleAvailable('HMACKeyHarness')
    this.keyPromise = (async () => {
      try {
        return await crypto.subtle.importKey(
          'jwk',
          this.normalized,
          { name: 'HMAC', hash: this.normalized.hash ?? 'SHA-256' },
          false,
          this.normalized.key_ops ?? ['sign', 'verify']
        )
      } catch {
        throw new CryptosuiteError(
          'ALGORITHM_UNSUPPORTED',
          'HMACKeyHarness: HMAC key is not supported by this WebCrypto runtime.'
        )
      }
    })()
  }

  async sign(bytes: Uint8Array): Promise<ArrayBuffer> {
    const key = await this.keyPromise
    return crypto.subtle.sign('HMAC', key, toBufferSource(bytes))
  }

  async verify(bytes: Uint8Array, signature: ArrayBuffer): Promise<boolean> {
    const key = await this.keyPromise
    return crypto.subtle.verify('HMAC', key, signature, toBufferSource(bytes))
  }
}
