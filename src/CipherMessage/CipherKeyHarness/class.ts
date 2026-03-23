import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { assertGetRandomValuesAvailable } from '../../.helpers/assertGetRandomValuesAvailable.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import { normalizeCipherJWK } from '../normalizeCipherJWK/index.js'
import type { CipherJWK, CipherMessageArtifact } from '../types/index.js'

export class CipherKeyHarness {
  private readonly keyPromise: Promise<CryptoKey>
  private readonly normalized: CipherJWK

  constructor(cipherJwk: CipherJWK) {
    this.normalized = normalizeCipherJWK(cipherJwk)
    assertSubtleAvailable('CipherKeyHarness')
    this.keyPromise = (async () => {
      try {
        return await crypto.subtle.importKey(
          'jwk',
          this.normalized,
          { name: CipherKeyHarness.#algorithmNameOf(this.normalized) },
          false,
          this.normalized.key_ops ?? ['encrypt', 'decrypt']
        )
      } catch {
        throw new CryptosuiteError(
          'ALGORITHM_UNSUPPORTED',
          'CipherKeyHarness: cipher key is not supported by this WebCrypto runtime.'
        )
      }
    })()
  }

  static #algorithmNameOf(
    cipherJwk: CipherJWK
  ): 'AES-GCM' | 'AES-CBC' | 'AES-CTR' {
    if (cipherJwk.alg.endsWith('GCM')) return 'AES-GCM'
    if (cipherJwk.alg.endsWith('CBC')) return 'AES-CBC'
    if (cipherJwk.alg.endsWith('CTR')) return 'AES-CTR'
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'CipherKeyHarness: unsupported cipher JWK alg.'
    )
  }

  async encrypt(plaintext: Uint8Array): Promise<CipherMessageArtifact> {
    const key = await this.keyPromise
    assertGetRandomValuesAvailable('CipherKeyHarness.encrypt')
    const algorithmName = CipherKeyHarness.#algorithmNameOf(this.normalized)

    if (algorithmName === 'AES-GCM') {
      const iv = crypto.getRandomValues(
        new Uint8Array(this.normalized.ivLength ?? 12)
      )
      const params: AesGcmParams = {
        name: 'AES-GCM',
        iv,
        ...(this.normalized.tagLength === undefined
          ? {}
          : { tagLength: this.normalized.tagLength }),
      }
      return {
        params,
        ciphertext: await crypto.subtle.encrypt(
          params,
          key,
          toBufferSource(plaintext)
        ),
      }
    }

    if (algorithmName === 'AES-CBC') {
      const iv = crypto.getRandomValues(
        new Uint8Array(this.normalized.ivLength ?? 16)
      )
      const params: AesCbcParams = { name: 'AES-CBC', iv }
      return {
        params,
        ciphertext: await crypto.subtle.encrypt(
          params,
          key,
          toBufferSource(plaintext)
        ),
      }
    }

    const counter = crypto.getRandomValues(
      new Uint8Array(this.normalized.ivLength ?? 16)
    )
    const params: AesCtrParams = {
      name: 'AES-CTR',
      counter,
      length: this.normalized.counterLength ?? 64,
    }

    return {
      params,
      ciphertext: await crypto.subtle.encrypt(
        params,
        key,
        toBufferSource(plaintext)
      ),
    }
  }

  async decrypt(artifact: CipherMessageArtifact): Promise<Uint8Array> {
    const key = await this.keyPromise
    if (
      !artifact ||
      typeof artifact !== 'object' ||
      !(artifact.ciphertext instanceof ArrayBuffer)
    ) {
      throw new CryptosuiteError(
        'CIPHER_ARTIFACT_INVALID',
        'CipherKeyHarness.decrypt: expected a cipher artifact with ciphertext and params.'
      )
    }

    const plaintext = await crypto.subtle.decrypt(
      artifact.params,
      key,
      artifact.ciphertext
    )
    return new Uint8Array(plaintext)
  }
}
