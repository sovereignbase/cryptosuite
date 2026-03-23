import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../../.errors/class.js'
import { assertSubtleAvailable } from '../../../.helpers/assertSubtleAvailable.js'
import type { SignJWK } from '../types/index.js'
import { normalizeSignJWK } from '../normalizeSignJWK/index.js'

function digestLengthOf(hash: string): number {
  if (hash === 'SHA-1') return 20
  if (hash === 'SHA-256') return 32
  if (hash === 'SHA-384') return 48
  if (hash === 'SHA-512') return 64
  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    'SignKeyHarness: unsupported signature digest.'
  )
}

export class SignKeyHarness {
  private readonly keyPromise: Promise<CryptoKey>
  private readonly operationAlgorithm: AlgorithmIdentifier

  constructor(signJwk: SignJWK) {
    assertSubtleAvailable('SignKeyHarness')

    const normalized = normalizeSignJWK(signJwk)
    const runtime = SignKeyHarness.#runtimeOf(normalized)
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
    return crypto.subtle.sign(
      this.operationAlgorithm,
      key,
      toBufferSource(bytes)
    )
  }

  static #runtimeOf(signJwk: SignJWK): {
    importAlgorithm: AlgorithmIdentifier
    operationAlgorithm: AlgorithmIdentifier
  } {
    if (
      signJwk.kty === 'OKP' &&
      (signJwk.crv === 'Ed25519' || signJwk.crv === 'Ed448')
    ) {
      return {
        importAlgorithm: { name: signJwk.crv },
        operationAlgorithm: signJwk.crv,
      }
    }

    if (
      signJwk.kty === 'EC' &&
      typeof signJwk.crv === 'string' &&
      signJwk.hash
    ) {
      return {
        importAlgorithm: {
          name: 'ECDSA',
          namedCurve: signJwk.crv,
        } as AlgorithmIdentifier,
        operationAlgorithm: {
          name: 'ECDSA',
          hash: { name: signJwk.hash },
        } as AlgorithmIdentifier,
      }
    }

    if (signJwk.kty === 'RSA' && signJwk.hash) {
      if (signJwk.alg === 'RSA-PSS' || /^PS\d+$/.test(signJwk.alg)) {
        return {
          importAlgorithm: {
            name: 'RSA-PSS',
            hash: { name: signJwk.hash },
          } as AlgorithmIdentifier,
          operationAlgorithm: {
            name: 'RSA-PSS',
            saltLength: signJwk.saltLength ?? digestLengthOf(signJwk.hash),
          } as AlgorithmIdentifier,
        }
      }

      return {
        importAlgorithm: {
          name: 'RSASSA-PKCS1-v1_5',
          hash: { name: signJwk.hash },
        } as AlgorithmIdentifier,
        operationAlgorithm: 'RSASSA-PKCS1-v1_5',
      }
    }

    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'SignKeyHarness: unsupported signature JWK.'
    )
  }
}
