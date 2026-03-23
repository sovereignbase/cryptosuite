import { CryptosuiteError } from '../../../.errors/class.js'
import { assertAesGcm256Key } from '../../../.helpers/assertAesGcm256Key.js'
import { assertRsaOaep4096PublicKey } from '../../../.helpers/assertRsaOaep4096PublicKey.js'
import { assertSubtleAvailable } from '../../../.helpers/assertSubtleAvailable.js'
import type { EncapsulateJWK } from '../types/index.js'
import type { CipherJWK } from '../../../Cipher/index.js'

export class EncapsulateAgent {
  private keyPromise: Promise<CryptoKey>
  constructor(encapsulateJwk: EncapsulateJWK) {
    assertRsaOaep4096PublicKey(encapsulateJwk, 'EncapsulateAgent')
    assertSubtleAvailable('EncapsulateAgent')
    this.keyPromise = (async () => {
      try {
        return await crypto.subtle.importKey(
          'jwk',
          encapsulateJwk,
          { name: 'RSA-OAEP', hash: 'SHA-256' },
          false,
          ['wrapKey']
        )
      } catch {
        throw new CryptosuiteError(
          'RSA_OAEP_UNSUPPORTED',
          'EncapsulateAgent: RSA-OAEP (4096/SHA-256) is not supported.'
        )
      }
    })()
  }

  async encapsulate(cipherJwk: CipherJWK): Promise<ArrayBuffer> {
    assertAesGcm256Key(cipherJwk, 'EncapsulateAgent.wrap')
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
        'EncapsulateAgent.wrap: AES-GCM is not supported.'
      )
    }

    try {
      return await crypto.subtle.wrapKey('jwk', aesKey, wrappingKey, {
        name: 'RSA-OAEP',
      })
    } catch {
      throw new CryptosuiteError(
        'RSA_OAEP_UNSUPPORTED',
        'EncapsulateAgent.wrap: RSA-OAEP (4096/SHA-256) is not supported.'
      )
    }
  }
}
