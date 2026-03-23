import { CryptosuiteError } from '../../../.errors/class.js'
import { assertSubtleAvailable } from '../../../.helpers/assertSubtleAvailable.js'
import { normalizeEncapsulateJWK } from '../../Encapsulator/normalizeEncapsulateJWK/index.js'
import { normalizeDecapsulateJWK } from '../normalizeDecapsulateJWK/index.js'
import type { DecapsulateJWK } from '../types/index.js'
import { resolveKeyAgreementAlgorithm } from '../../resolveKeyAgreementAlgorithm/index.js'
import { resolveSharedKeyContext } from '../../resolveSharedKeyContext/index.js'
import type {
  KeyAgreementArtifact,
  SharedKeyContext,
  SharedKeyJWK,
} from '../../types/index.js'

export class DecapsulateJWKHarness {
  private readonly normalized: DecapsulateJWK
  private readonly strategy: ReturnType<typeof resolveKeyAgreementAlgorithm>
  private readonly keyPromise: Promise<CryptoKey>

  constructor(private readonly decapsulateJwk: DecapsulateJWK) {
    assertSubtleAvailable('DecapsulateJWKHarness')
    this.normalized = normalizeDecapsulateJWK(decapsulateJwk)
    this.strategy = resolveKeyAgreementAlgorithm(this.normalized)
    this.keyPromise = this.importKey()
  }

  private async importKey(): Promise<CryptoKey> {
    try {
      return await crypto.subtle.importKey(
        'jwk',
        this.normalized,
        this.strategy.importAlgorithm,
        false,
        this.strategy.privateKeyUsages
      )
    } catch {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'DecapsulateJWKHarness: selected key agreement JWK is not supported by this WebCrypto runtime.'
      )
    }
  }

  async unwrap(ciphertext: BufferSource): Promise<SharedKeyJWK> {
    if (this.strategy.mode !== 'wrap') {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'DecapsulateJWKHarness.unwrap: unwrap() is available only for RSA-OAEP key agreement JWKs.'
      )
    }

    const sharedKey = resolveSharedKeyContext()
    const unwrappingKey = await this.keyPromise
    const sharedCryptoKey = await crypto.subtle.unwrapKey(
      'jwk',
      ciphertext,
      unwrappingKey,
      this.strategy.wrapAlgorithm,
      sharedKey.keyAlgorithm,
      true,
      sharedKey.keyUsages
    )

    return sharedKey.normalize(await crypto.subtle.exportKey('jwk', sharedCryptoKey))
  }

  async decapsulate(
    artifact: KeyAgreementArtifact,
    context: SharedKeyContext = {}
  ): Promise<{ sharedJwk: SharedKeyJWK }> {
    const sharedKey = resolveSharedKeyContext(context)

    if (this.strategy.mode === 'wrap') {
      if (artifact.kind !== 'wrapKey') {
        throw new CryptosuiteError(
          'KEY_AGREEMENT_ARTIFACT_INVALID',
          'DecapsulateJWKHarness.decapsulate: RSA-OAEP decapsulation expects a wrapKey artifact.'
        )
      }

      const unwrappingKey = await this.keyPromise
      const sharedCryptoKey = await crypto.subtle.unwrapKey(
        'jwk',
        artifact.ciphertext,
        unwrappingKey,
        this.strategy.wrapAlgorithm,
        sharedKey.keyAlgorithm,
        true,
        sharedKey.keyUsages
      )

      return {
        sharedJwk: sharedKey.normalize(
          await crypto.subtle.exportKey('jwk', sharedCryptoKey)
        ),
      }
    }

    if (artifact.kind !== 'deriveKey') {
      throw new CryptosuiteError(
        'KEY_AGREEMENT_ARTIFACT_INVALID',
        'DecapsulateJWKHarness.decapsulate: derived key agreement expects a deriveKey artifact.'
      )
    }

    const privateKey = await this.keyPromise
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      normalizeEncapsulateJWK(artifact.ephemeralPublicJwk),
      this.strategy.importAlgorithm,
      false,
      this.strategy.publicKeyUsages
    )

    const sharedCryptoKey = await crypto.subtle.deriveKey(
      {
        name: this.strategy.deriveAlgorithmName,
        public: publicKey,
      },
      privateKey,
      sharedKey.keyAlgorithm,
      true,
      sharedKey.keyUsages
    )

    return {
      sharedJwk: sharedKey.normalize(
        await crypto.subtle.exportKey('jwk', sharedCryptoKey)
      ),
    }
  }
}
