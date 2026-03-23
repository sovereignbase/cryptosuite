import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../../.errors/class.js'
import { assertSubtleAvailable } from '../../../.helpers/assertSubtleAvailable.js'
import { normalizeVerifyJWK } from '../normalizeVerifyJWK/index.js'
import type { VerifyJWK } from '../types/index.js'

function digestLengthOf(hash: string): number {
  if (hash === 'SHA-1') return 20
  if (hash === 'SHA-256') return 32
  if (hash === 'SHA-384') return 48
  if (hash === 'SHA-512') return 64
  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    'VerifyKeyHarness: unsupported signature digest.'
  )
}

export class VerifyKeyHarness {
  private readonly keyPromise: Promise<CryptoKey>
  private readonly operationAlgorithm: AlgorithmIdentifier = ''
  constructor(verifyJwk: VerifyJWK) {
    assertSubtleAvailable('VerifyKeyHarness')

    const normalized = normalizeVerifyJWK(verifyJwk)
    const runtime = VerifyKeyHarness.#runtimeOf(normalized)
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

  static #runtimeOf(verifyJwk: VerifyJWK): {
    importAlgorithm: AlgorithmIdentifier
    operationAlgorithm: AlgorithmIdentifier
  } {
    if (
      verifyJwk.kty === 'OKP' &&
      (verifyJwk.crv === 'Ed25519' || verifyJwk.crv === 'Ed448')
    ) {
      return {
        importAlgorithm: { name: verifyJwk.crv },
        operationAlgorithm: verifyJwk.crv,
      }
    }

    if (
      verifyJwk.kty === 'EC' &&
      typeof verifyJwk.crv === 'string' &&
      verifyJwk.hash
    ) {
      return {
        importAlgorithm: {
          name: 'ECDSA',
          namedCurve: verifyJwk.crv,
        } as AlgorithmIdentifier,
        operationAlgorithm: {
          name: 'ECDSA',
          hash: { name: verifyJwk.hash },
        } as AlgorithmIdentifier,
      }
    }

    if (verifyJwk.kty === 'RSA' && verifyJwk.hash) {
      if (verifyJwk.alg === 'RSA-PSS' || /^PS\d+$/.test(verifyJwk.alg)) {
        return {
          importAlgorithm: {
            name: 'RSA-PSS',
            hash: { name: verifyJwk.hash },
          } as AlgorithmIdentifier,
          operationAlgorithm: {
            name: 'RSA-PSS',
            saltLength: verifyJwk.saltLength ?? digestLengthOf(verifyJwk.hash),
          } as AlgorithmIdentifier,
        }
      }

      return {
        importAlgorithm: {
          name: 'RSASSA-PKCS1-v1_5',
          hash: { name: verifyJwk.hash },
        } as AlgorithmIdentifier,
        operationAlgorithm: 'RSASSA-PKCS1-v1_5',
      }
    }

    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'VerifyKeyHarness: unsupported signature JWK.'
    )
  }
}
