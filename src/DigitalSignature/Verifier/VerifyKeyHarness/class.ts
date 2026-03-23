import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../../.errors/class.js'
import { assertSubtleAvailable } from '../../../.helpers/assertSubtleAvailable.js'
import { normalizeVerifyJWK } from '../normalizeVerifyJWK/index.js'
import type { VerifyJWK } from '../types/index.js'
import { resolveDigitalSignatureAlgorithm } from '../../resolveDigitalSignatureAlgorithm/index.js'

export class VerifyKeyHarness {
  private keyPromise: Promise<CryptoKey>
  private operationAlgorithm: AlgorithmIdentifier = ''
  constructor(verifyJwk: VerifyJWK) {
    assertSubtleAvailable('VerifyKeyHarness')

    const normalized = normalizeVerifyJWK(verifyJwk)
    const runtime = resolveDigitalSignatureAlgorithm(normalized)
    this.operationAlgorithm = runtime.operationAlgorithm

    this.keyPromise = (async () => {
      try {
        return await crypto.subtle.importKey(
          'jwk',
          normalized,
          runtime.importAlgorithm,
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
      this.operationAlgorithm,
      key,
      signature,
      toBufferSource(bytes)
    )
  }
}
