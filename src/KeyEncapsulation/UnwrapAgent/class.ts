import { CryptosuiteError } from '../../.errors/class.js'
import { assertAesGcm256Key } from '../../.helpers/assertAesGcm256Key.js'
import { assertRsaOaep4096PrivateKey } from '../../.helpers/assertRsaOaep4096PrivateKey.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import type { UnwrapJWK } from '../index.js'
import type { CipherJWK } from '../../Cipher/index.js'

export class UnwrapAgent {
  private keyPromise: Promise<CryptoKey>
  constructor(unwrapJwk: UnwrapJWK) {
    assertRsaOaep4096PrivateKey(unwrapJwk, 'UnwrapAgent')
    assertSubtleAvailable('UnwrapAgent')
    this.keyPromise = (async () => {
      try {
        return await crypto.subtle.importKey(
          'jwk',
          unwrapJwk,
          { name: 'RSA-OAEP', hash: 'SHA-256' },
          false,
          ['unwrapKey']
        )
      } catch {
        throw new CryptosuiteError(
          'RSA_OAEP_UNSUPPORTED',
          'UnwrapAgent: RSA-OAEP (4096/SHA-256) is not supported.'
        )
      }
    })()
  }

  async unwrap(wrapped: ArrayBuffer): Promise<CipherJWK> {
    const unwrappingKey = await this.keyPromise

    let aesKey: CryptoKey
    try {
      aesKey = await crypto.subtle.unwrapKey(
        'jwk',
        wrapped,
        unwrappingKey,
        { name: 'RSA-OAEP' },
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      )
    } catch {
      throw new CryptosuiteError(
        'RSA_OAEP_UNSUPPORTED',
        'UnwrapAgent.unwrap: RSA-OAEP (4096/SHA-256) is not supported.'
      )
    }

    const jwk = (await crypto.subtle.exportKey('jwk', aesKey)) as CipherJWK
    assertAesGcm256Key(jwk, 'UnwrapAgent.unwrap')
    return jwk
  }
}
