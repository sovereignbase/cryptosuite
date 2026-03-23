import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../../.errors/class.js'
import { assertSubtleAvailable } from '../../../.helpers/assertSubtleAvailable.js'
import type { SignJWK } from '../types/index.js'
import { normalizeSignJWK } from '../normalizeSignJWK/index.js'
import { resolveDigitalSignatureAlgorithm } from '../../resolveDigitalSignatureAlgorithm/index.js'

export class SignKeyHarness {
  private keyPromise: Promise<CryptoKey>
  private operationAlgorithm: AlgorithmIdentifier = ''

  constructor(signJwk: SignJWK) {
    assertSubtleAvailable('SignKeyHarness')

    const normalized = normalizeSignJWK(signJwk)
    const runtime = resolveDigitalSignatureAlgorithm(normalized)
    this.operationAlgorithm = runtime.operationAlgorithm

    this.keyPromise = (async () => {
      try {
        return await crypto.subtle.importKey(
          'jwk',
          normalized,
          runtime.importAlgorithm,
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
    return crypto.subtle.sign(this.operationAlgorithm, key, toBufferSource(bytes))
  }
}
