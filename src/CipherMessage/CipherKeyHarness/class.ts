import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { assertAesGcm256Key } from '../../.helpers/assertAesGcm256Key.js'
import { assertAesGcmIv96 } from '../../.helpers/assertAesGcmIv96.js'
import { assertGetRandomValuesAvailable } from '../../.helpers/assertGetRandomValuesAvailable.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import type { CipherJWK } from '../index.js'
export class CipherAgent {
  private keyPromise: Promise<CryptoKey>
  constructor(cipherJwk: CipherJWK) {
    assertAesGcm256Key(cipherJwk, 'CipherAgent')
    assertSubtleAvailable('CipherAgent')
    this.keyPromise = (async () => {
      try {
        return await crypto.subtle.importKey(
          'jwk',
          cipherJwk,
          { name: 'AES-GCM' },
          false,
          ['encrypt', 'decrypt']
        )
      } catch {
        throw new CryptosuiteError(
          'AES_GCM_UNSUPPORTED',
          'CipherAgent: AES-GCM is not supported.'
        )
      }
    })()
  }

  async encrypt(
    plaintext: Uint8Array
  ): Promise<{ iv: Uint8Array; ciphertext: ArrayBuffer }> {
    const key = await this.keyPromise
    assertGetRandomValuesAvailable('CipherAgent.encrypt')
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      toBufferSource(plaintext)
    )
    return { iv, ciphertext }
  }

  async decrypt({
    iv,
    ciphertext,
  }: {
    iv: Uint8Array
    ciphertext: ArrayBuffer
  }): Promise<Uint8Array> {
    const key = await this.keyPromise
    assertAesGcmIv96(iv, 'CipherAgent.decrypt')
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toBufferSource(iv) },
      key,
      ciphertext
    )
    return new Uint8Array(plaintext)
  }
}
