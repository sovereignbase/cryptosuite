import { toBufferSource } from '@z-base/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { assertHmacSha256Key } from '../../.helpers/assertHmacSha256Key.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import type { HMACJWK } from '../index.js'

export class HMACAgent {
  private keyPromise: Promise<CryptoKey>

  constructor(hmacJwk: HMACJWK) {
    assertHmacSha256Key(hmacJwk, 'HMACAgent')
    assertSubtleAvailable('HMACAgent')
    this.keyPromise = (async () => {
      try {
        return await crypto.subtle.importKey(
          'jwk',
          hmacJwk,
          { name: 'HMAC', hash: 'SHA-256' },
          false,
          ['sign', 'verify']
        )
      } catch {
        throw new CryptosuiteError(
          'HMAC_SHA256_UNSUPPORTED',
          'HMACAgent: HMAC-SHA-256 is not supported.'
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
