import { CryptosuiteError } from '../../../.errors/class.js'
import { assertSubtleAvailable } from '../../../.helpers/assertSubtleAvailable.js'
import { normalizeCipherJWK } from '../../../CipherMessage/.core/helpers/validateKeyByAlgCode/index.js'
import type { CipherJWK } from '../../../CipherMessage/.core/types/index.js'
import { normalizeEncapsulateJWK } from '../normalizeEncapsulateJWK/index.js'
import type { EncapsulateJWK } from '../types/index.js'
import type { KeyAgreementArtifact } from '../../types/index.js'

type KeyAgreementStrategy =
  | {
      mode: 'wrap'
      importAlgorithm: AlgorithmIdentifier
      publicKeyUsages: KeyUsage[]
      wrapAlgorithm: AlgorithmIdentifier
    }
  | {
      mode: 'derive'
      importAlgorithm: AlgorithmIdentifier
      publicKeyUsages: KeyUsage[]
      privateKeyUsages: KeyUsage[]
      generateAlgorithm: AlgorithmIdentifier
      deriveAlgorithmName: 'ECDH' | 'X25519' | 'X448'
    }

type SharedCipherRuntime = {
  keyAlgorithm: AlgorithmIdentifier
  keyUsages: KeyUsage[]
  normalize: (jwk: JsonWebKey) => CipherJWK
}

function hashOf(alg: string): string | undefined {
  if (alg === 'RSA-OAEP') return 'SHA-1'
  if (alg === 'RSA-OAEP-256') return 'SHA-256'
  if (alg === 'RSA-OAEP-384') return 'SHA-384'
  if (alg === 'RSA-OAEP-512') return 'SHA-512'
  return undefined
}

function strategyOf(encapsulateJwk: EncapsulateJWK): KeyAgreementStrategy {
  if (encapsulateJwk.kty === 'RSA') {
    const hash = encapsulateJwk.hash ?? hashOf(encapsulateJwk.alg)
    if (!hash) {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'EncapsulateKeyHarness: unsupported RSA-OAEP JWK alg.'
      )
    }

    return {
      mode: 'wrap',
      importAlgorithm: {
        name: 'RSA-OAEP',
        hash: { name: hash },
      } as AlgorithmIdentifier,
      publicKeyUsages: ['wrapKey'],
      wrapAlgorithm: { name: 'RSA-OAEP' },
    }
  }

  if (encapsulateJwk.kty === 'EC' && typeof encapsulateJwk.crv === 'string') {
    return {
      mode: 'derive',
      importAlgorithm: {
        name: 'ECDH',
        namedCurve: encapsulateJwk.crv,
      } as AlgorithmIdentifier,
      publicKeyUsages: [],
      privateKeyUsages: ['deriveKey', 'deriveBits'],
      generateAlgorithm: {
        name: 'ECDH',
        namedCurve: encapsulateJwk.crv,
      } as AlgorithmIdentifier,
      deriveAlgorithmName: 'ECDH',
    }
  }

  if (
    encapsulateJwk.kty === 'OKP' &&
    (encapsulateJwk.crv === 'X25519' || encapsulateJwk.crv === 'X448')
  ) {
    return {
      mode: 'derive',
      importAlgorithm: {
        name: encapsulateJwk.crv,
      },
      publicKeyUsages: [],
      privateKeyUsages: ['deriveKey', 'deriveBits'],
      generateAlgorithm: {
        name: encapsulateJwk.crv,
      },
      deriveAlgorithmName: encapsulateJwk.crv,
    }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    'EncapsulateKeyHarness: unsupported key agreement JWK.'
  )
}

function sharedCipherRuntimeOf(
  keyAgreementJwk: Pick<
    EncapsulateJWK,
    'cipherAlg' | 'ivLength' | 'tagLength' | 'counterLength'
  >
): SharedCipherRuntime {
  const match = /^A(?<length>\d+)(?<mode>GCM|CBC|CTR)$/.exec(
    keyAgreementJwk.cipherAlg
  )
  if (!match?.groups) {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'EncapsulateKeyHarness: unsupported cipher declaration.'
    )
  }

  const name = `AES-${match.groups.mode}` as 'AES-GCM' | 'AES-CBC' | 'AES-CTR'
  const length = Number(match.groups.length)

  return {
    keyAlgorithm: { name, length } as AlgorithmIdentifier,
    keyUsages: ['encrypt', 'decrypt'],
    normalize: (jwk: JsonWebKey) => {
      return normalizeCipherJWK({
        ...jwk,
        alg: keyAgreementJwk.cipherAlg,
        ...(keyAgreementJwk.ivLength === undefined
          ? {}
          : { ivLength: keyAgreementJwk.ivLength }),
        ...(keyAgreementJwk.tagLength === undefined
          ? {}
          : { tagLength: keyAgreementJwk.tagLength }),
        ...(keyAgreementJwk.counterLength === undefined
          ? {}
          : { counterLength: keyAgreementJwk.counterLength }),
      })
    },
  }
}

function serializeArtifactCiphertext(jwk: JsonWebKey): ArrayBuffer {
  const bytes = new TextEncoder().encode(JSON.stringify(jwk))
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  )
}

export class EncapsulateKeyHarness {
  private readonly normalized: EncapsulateJWK
  private readonly strategy: KeyAgreementStrategy
  private readonly keyPromise: Promise<CryptoKey>

  constructor(encapsulateJwk: EncapsulateJWK) {
    assertSubtleAvailable('EncapsulateKeyHarness')
    this.normalized = normalizeEncapsulateJWK(encapsulateJwk)
    this.strategy = strategyOf(this.normalized)
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
        'EncapsulateKeyHarness: selected key agreement JWK is not supported by this WebCrypto runtime.'
      )
    }
  }

  async encapsulate(): Promise<{
    artifact: KeyAgreementArtifact
    cipherJwk: CipherJWK
  }> {
    const sharedCipher = sharedCipherRuntimeOf(this.normalized)

    if (this.strategy.mode === 'wrap') {
      const wrappingKey = await this.keyPromise

      try {
        const sharedCryptoKey = (await crypto.subtle.generateKey(
          sharedCipher.keyAlgorithm,
          true,
          sharedCipher.keyUsages
        )) as CryptoKey

        const ciphertext = await crypto.subtle.wrapKey(
          'jwk',
          sharedCryptoKey,
          wrappingKey,
          this.strategy.wrapAlgorithm
        )

        return {
          artifact: { ciphertext },
          cipherJwk: sharedCipher.normalize(
            await crypto.subtle.exportKey('jwk', sharedCryptoKey)
          ),
        }
      } catch {
        throw new CryptosuiteError(
          'ENCAPSULATION_FAILED',
          'EncapsulateKeyHarness.encapsulate: failed to encapsulate the cipher JWK.'
        )
      }
    }

    const recipientPublicKey = await this.keyPromise

    try {
      const ephemeralPair = (await crypto.subtle.generateKey(
        this.strategy.generateAlgorithm,
        true,
        this.strategy.privateKeyUsages
      )) as CryptoKeyPair

      const sharedCryptoKey = await crypto.subtle.deriveKey(
        {
          name: this.strategy.deriveAlgorithmName,
          public: recipientPublicKey,
        } as AlgorithmIdentifier,
        ephemeralPair.privateKey,
        sharedCipher.keyAlgorithm,
        true,
        sharedCipher.keyUsages
      )

      return {
        artifact: {
          ciphertext: serializeArtifactCiphertext(
            (await crypto.subtle.exportKey(
              'jwk',
              ephemeralPair.publicKey
            )) as JsonWebKey
          ),
        },
        cipherJwk: sharedCipher.normalize(
          await crypto.subtle.exportKey('jwk', sharedCryptoKey)
        ),
      }
    } catch {
      throw new CryptosuiteError(
        'ENCAPSULATION_FAILED',
        'EncapsulateKeyHarness.encapsulate: failed to derive the cipher JWK.'
      )
    }
  }
}
