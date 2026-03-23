import { CryptosuiteError } from '../../../.errors/class.js'
import { assertSubtleAvailable } from '../../../.helpers/assertSubtleAvailable.js'
import { normalizeCipherJWK } from '../../../Cipher/normalizeCipherJWK/index.js'
import { normalizeDecapsulateJWK } from '../normalizeDecapsulateJWK/index.js'
import type { DecapsulateJWK } from '../types/index.js'
import type { CipherJWK } from '../../../Cipher/types/index.js'

function getImportParamsFromAlgorithmName(
  algorithm: string
): RsaHashedImportParams {
  if (algorithm === 'RSA-OAEP') {
    return { name: 'RSA-OAEP', hash: { name: 'SHA-1' } }
  }
  if (algorithm === 'RSA-OAEP-256') {
    return { name: 'RSA-OAEP', hash: { name: 'SHA-256' } }
  }
  if (algorithm === 'RSA-OAEP-384') {
    return { name: 'RSA-OAEP', hash: { name: 'SHA-384' } }
  }
  if (algorithm === 'RSA-OAEP-512') {
    return { name: 'RSA-OAEP', hash: { name: 'SHA-512' } }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    'UnwrapCryptoKeyHarness: unwrapKey() harness supports only RSA-OAEP algorithms. Use a deriveKey/deriveBits harness for ECDH/X25519/X448.'
  )
}

function getUnwrapParamsFromAlgorithmName(algorithm: string): RsaOaepParams {
  if (
    algorithm === 'RSA-OAEP' ||
    algorithm === 'RSA-OAEP-256' ||
    algorithm === 'RSA-OAEP-384' ||
    algorithm === 'RSA-OAEP-512'
  ) {
    return { name: 'RSA-OAEP' }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    'UnwrapCryptoKeyHarness: unsupported unwrap algorithm.'
  )
}

export class UnwrapCryptoKeyHarness {
  private keyPromise: Promise<CryptoKey>
  private keyAlgorithm = ''

  constructor(decapsulateJwk: UnwrapJWK) {
    assertSubtleAvailable('UnwrapCryptoKeyHarness')

    const normalized = normalizeDecapsulateJWK(decapsulateJwk)
    this.keyAlgorithm = normalized.alg

    this.keyPromise = (async () => {
      try {
        return await crypto.subtle.importKey(
          'jwk',
          normalized,
          getImportParamsFromAlgorithmName(this.keyAlgorithm),
          false,
          ['unwrapKey']
        )
      } catch {
        throw new CryptosuiteError(
          'ALGORITHM_UNSUPPORTED',
          'UnwrapCryptoKeyHarness: selected algorithm is not supported by this WebCrypto runtime.'
        )
      }
    })()
  }

  async decapsulate(
    wrapped: BufferSource,
    unwrappedKeyAlgorithm: AesKeyAlgorithm,
    extractable: boolean = true,
    keyUsages: KeyUsage[] = ['encrypt', 'decrypt']
  ): Promise<CipherJWK> {
    const unwrappingKey = await this.keyPromise

    let key: CryptoKey
    try {
      key = await crypto.subtle.unwrapKey(
        'jwk',
        wrapped,
        unwrappingKey,
        getUnwrapParamsFromAlgorithmName(this.keyAlgorithm),
        unwrappedKeyAlgorithm,
        extractable,
        keyUsages
      )
    } catch {
      throw new CryptosuiteError(
        'DECAPSULATION_FAILED',
        'UnwrapCryptoKeyHarness.unwrap: failed to unwrap key with the provided parameters.'
      )
    }

    let jwk: JsonWebKey
    try {
      jwk = await crypto.subtle.exportKey('jwk', key)
    } catch {
      throw new CryptosuiteError(
        'EXPORT_FAILED',
        'UnwrapCryptoKeyHarness.unwrap: failed to export unwrapped key as JWK.'
      )
    }

    return normalizeCipherJWK(jwk)
  }
}
