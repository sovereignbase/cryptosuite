import { CryptosuiteError } from '../../.errors/class.js'
import { assertAesGcm256Key } from '../../.helpers/assertAesGcm256Key.js'
import { assertRsaOaep4096PublicKey } from '../../.helpers/assertRsaOaep4096PublicKey.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import type { WrapJWK } from '../index.js'
import type { CipherJWK } from '../../Cipher/index.js'

export class WrapAgent {
  private keyPromise: Promise<CryptoKey>
  constructor(wrapJwk: WrapJWK) {
    assertRsaOaep4096PublicKey(wrapJwk, 'WrapAgent')
    assertSubtleAvailable('WrapAgent')
    this.keyPromise = (async () => {
      try {
        return await crypto.subtle.importKey(
          'jwk',
          wrapJwk,
          { name: 'RSA-OAEP', hash: 'SHA-256' },
          false,
          ['wrapKey']
        )
      } catch {
        throw new CryptosuiteError(
          'RSA_OAEP_UNSUPPORTED',
          'WrapAgent: RSA-OAEP (4096/SHA-256) is not supported.'
        )
      }
    })()
  }

  async wrap(cipherJwk: CipherJWK): Promise<ArrayBuffer> {
    assertAesGcm256Key(cipherJwk, 'WrapAgent.wrap')
    const wrappingKey = await this.keyPromise

    let aesKey: CryptoKey
    try {
      aesKey = await crypto.subtle.importKey(
        'jwk',
        cipherJwk,
        { name: 'AES-GCM' },
        true,
        ['encrypt', 'decrypt']
      )
    } catch {
      throw new CryptosuiteError(
        'AES_GCM_UNSUPPORTED',
        'WrapAgent.wrap: AES-GCM is not supported.'
      )
    }

    try {
      return await crypto.subtle.wrapKey('jwk', aesKey, wrappingKey, {
        name: 'RSA-OAEP',
      })
    } catch {
      throw new CryptosuiteError(
        'RSA_OAEP_UNSUPPORTED',
        'WrapAgent.wrap: RSA-OAEP (4096/SHA-256) is not supported.'
      )
    }
  }
}
