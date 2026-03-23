import { CryptosuiteError } from '../../../.errors/class.js'
import { assertSubtleAvailable } from '../../../.helpers/assertSubtleAvailable.js'
import { normalizeCipherJWK } from '../../../Cipher/normalizeCipherJWK/index.js'
import type { CipherJWK } from '../../../Cipher/types/index.js'
import { normalizeEncapsulateJWK } from '../normalizeEncapsulateJWK/index.js'
import type { EncapsulateJWK } from '../types/index.js'
import { resolveKeyAgreementAlgorithm } from '../../resolveKeyAgreementAlgorithm/index.js'
import { resolveSharedKeyContext } from '../../resolveSharedKeyContext/index.js'
import type {
  KeyAgreementArtifact,
  SharedKeyContext,
  SharedKeyJWK,
} from '../../types/index.js'

export class EncapsulateJWKHarness {
  private readonly normalized: EncapsulateJWK
  private readonly strategy: ReturnType<typeof resolveKeyAgreementAlgorithm>
  private readonly keyPromise: Promise<CryptoKey>

  constructor(private readonly encapsulateJwk: EncapsulateJWK) {
    assertSubtleAvailable('EncapsulateJWKHarness')
    this.normalized = normalizeEncapsulateJWK(encapsulateJwk)
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
        this.strategy.publicKeyUsages
      )
    } catch {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'EncapsulateJWKHarness: selected key agreement JWK is not supported by this WebCrypto runtime.'
      )
    }
  }

  async wrap(cipherJwk: CipherJWK): Promise<ArrayBuffer> {
    if (this.strategy.mode !== 'wrap') {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'EncapsulateJWKHarness.wrap: wrap() is available only for RSA-OAEP key agreement JWKs.'
      )
    }

    const wrappingKey = await this.keyPromise
    const normalizedCipherJwk = normalizeCipherJWK(cipherJwk)
    try {
      const aesKey = await crypto.subtle.importKey(
        'jwk',
        normalizedCipherJwk,
        { name: 'AES-GCM' },
        true,
        ['encrypt', 'decrypt']
      )
      return await crypto.subtle.wrapKey(
        'jwk',
        aesKey,
        wrappingKey,
        this.strategy.wrapAlgorithm
      )
    } catch {
      throw new CryptosuiteError(
        'ENCAPSULATION_FAILED',
        'EncapsulateJWKHarness.wrap: failed to wrap the supplied cipher JWK.'
      )
    }
  }

  async encapsulate(
    context: SharedKeyContext = {}
  ): Promise<{ artifact: KeyAgreementArtifact; sharedJwk: SharedKeyJWK }> {
    const sharedKey = resolveSharedKeyContext(context)

    if (this.strategy.mode === 'wrap') {
      const sharedJwk = await sharedKey.generate()
      const wrappingKey = await this.keyPromise
      const sharedCryptoKey = await crypto.subtle.importKey(
        'jwk',
        sharedJwk,
        sharedKey.keyAlgorithm,
        true,
        sharedKey.keyUsages
      )
      const ciphertext = await crypto.subtle.wrapKey(
        'jwk',
        sharedCryptoKey,
        wrappingKey,
        this.strategy.wrapAlgorithm
      )
      return { artifact: { kind: 'wrapKey', ciphertext }, sharedJwk }
    }

    const recipientPublicKey = await this.keyPromise
    const ephemeralPair = (await crypto.subtle.generateKey(
      this.strategy.generateAlgorithm,
      true,
      this.strategy.privateKeyUsages
    )) as CryptoKeyPair

    const sharedCryptoKey = await crypto.subtle.deriveKey(
      {
        name: this.strategy.deriveAlgorithmName,
        public: recipientPublicKey,
      },
      ephemeralPair.privateKey,
      sharedKey.keyAlgorithm,
      true,
      sharedKey.keyUsages
    )

    const ephemeralPublicJwk = normalizeEncapsulateJWK({
      ...(await crypto.subtle.exportKey('jwk', ephemeralPair.publicKey)),
      alg: this.normalized.alg,
      use: 'enc',
      key_ops: [],
    })

    return {
      artifact: { kind: 'deriveKey', ephemeralPublicJwk },
      sharedJwk: sharedKey.normalize(
        await crypto.subtle.exportKey('jwk', sharedCryptoKey)
      ),
    }
  }
}
