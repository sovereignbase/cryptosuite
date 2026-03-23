import { CryptosuiteError } from '../../../.errors/class.js'
import { assertSubtleAvailable } from '../../../.helpers/assertSubtleAvailable.js'
import { normalizeCipherJWK } from '../../../CipherMessage/normalizeCipherJWK/index.js'
import type { CipherJWK } from '../../../CipherMessage/types/index.js'
import { normalizeEncapsulateJWK } from '../../Encapsulator/normalizeEncapsulateJWK/index.js'
import { normalizeDecapsulateJWK } from '../normalizeDecapsulateJWK/index.js'
import type { DecapsulateJWK } from '../types/index.js'
import type { KeyAgreementArtifact } from '../../types/index.js'

type KeyAgreementStrategy =
  | {
      mode: 'wrap'
      importAlgorithm: AlgorithmIdentifier
      privateKeyUsages: KeyUsage[]
      unwrapAlgorithm: AlgorithmIdentifier
    }
  | {
      mode: 'derive'
      importAlgorithm: AlgorithmIdentifier
      publicKeyUsages: KeyUsage[]
      privateKeyUsages: KeyUsage[]
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

function strategyOf(decapsulateJwk: DecapsulateJWK): KeyAgreementStrategy {
  if (decapsulateJwk.kty === 'RSA') {
    const hash = decapsulateJwk.hash ?? hashOf(decapsulateJwk.alg)
    if (!hash) {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'DecapsulateKeyHarness: unsupported RSA-OAEP JWK alg.'
      )
    }

    return {
      mode: 'wrap',
      importAlgorithm: {
        name: 'RSA-OAEP',
        hash: { name: hash },
      } as AlgorithmIdentifier,
      privateKeyUsages: ['unwrapKey'],
      unwrapAlgorithm: { name: 'RSA-OAEP' },
    }
  }

  if (decapsulateJwk.kty === 'EC' && typeof decapsulateJwk.crv === 'string') {
    return {
      mode: 'derive',
      importAlgorithm: {
        name: 'ECDH',
        namedCurve: decapsulateJwk.crv,
      } as AlgorithmIdentifier,
      publicKeyUsages: [],
      privateKeyUsages: ['deriveKey', 'deriveBits'],
      deriveAlgorithmName: 'ECDH',
    }
  }

  if (
    decapsulateJwk.kty === 'OKP' &&
    (decapsulateJwk.crv === 'X25519' || decapsulateJwk.crv === 'X448')
  ) {
    return {
      mode: 'derive',
      importAlgorithm: {
        name: decapsulateJwk.crv,
      },
      publicKeyUsages: [],
      privateKeyUsages: ['deriveKey', 'deriveBits'],
      deriveAlgorithmName: decapsulateJwk.crv,
    }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    'DecapsulateKeyHarness: unsupported key agreement JWK.'
  )
}

function sharedCipherRuntimeOf(
  keyAgreementJwk: Pick<
    DecapsulateJWK,
    'cipherAlg' | 'ivLength' | 'tagLength' | 'counterLength'
  >
): SharedCipherRuntime {
  const match = /^A(?<length>\d+)(?<mode>GCM|CBC|CTR)$/.exec(
    keyAgreementJwk.cipherAlg
  )
  if (!match?.groups) {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'DecapsulateKeyHarness: unsupported cipher declaration.'
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

function encapsulateJwkOf(ciphertext: ArrayBuffer): JsonWebKey {
  let parsed: unknown

  try {
    parsed = JSON.parse(new TextDecoder().decode(new Uint8Array(ciphertext)))
  } catch {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_ARTIFACT_INVALID',
      'DecapsulateKeyHarness.decapsulate: invalid encapsulation artifact.'
    )
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_ARTIFACT_INVALID',
      'DecapsulateKeyHarness.decapsulate: invalid encapsulation artifact.'
    )
  }

  return parsed as JsonWebKey
}

export class DecapsulateKeyHarness {
  private readonly normalized: DecapsulateJWK
  private readonly strategy: KeyAgreementStrategy
  private readonly keyPromise: Promise<CryptoKey>

  constructor(decapsulateJwk: DecapsulateJWK) {
    assertSubtleAvailable('DecapsulateKeyHarness')
    this.normalized = normalizeDecapsulateJWK(decapsulateJwk)
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
        this.strategy.privateKeyUsages
      )
    } catch {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'DecapsulateKeyHarness: selected key agreement JWK is not supported by this WebCrypto runtime.'
      )
    }
  }

  async decapsulate(
    artifact: KeyAgreementArtifact
  ): Promise<{ cipherJwk: CipherJWK }> {
    if (
      !artifact ||
      typeof artifact !== 'object' ||
      !(artifact.ciphertext instanceof ArrayBuffer)
    ) {
      throw new CryptosuiteError(
        'KEY_AGREEMENT_ARTIFACT_INVALID',
        'DecapsulateKeyHarness.decapsulate: expected an artifact with ciphertext.'
      )
    }

    const sharedCipher = sharedCipherRuntimeOf(this.normalized)

    if (this.strategy.mode === 'wrap') {
      const unwrappingKey = await this.keyPromise

      try {
        const sharedCryptoKey = await crypto.subtle.unwrapKey(
          'jwk',
          artifact.ciphertext,
          unwrappingKey,
          this.strategy.unwrapAlgorithm,
          sharedCipher.keyAlgorithm,
          true,
          sharedCipher.keyUsages
        )

        return {
          cipherJwk: sharedCipher.normalize(
            await crypto.subtle.exportKey('jwk', sharedCryptoKey)
          ),
        }
      } catch {
        throw new CryptosuiteError(
          'DECAPSULATION_FAILED',
          'DecapsulateKeyHarness.decapsulate: failed to decapsulate the cipher JWK.'
        )
      }
    }

    const privateKey = await this.keyPromise

    try {
      const publicKey = await crypto.subtle.importKey(
        'jwk',
        normalizeEncapsulateJWK({
          ...encapsulateJwkOf(artifact.ciphertext),
          alg: this.normalized.alg,
          cipherAlg: this.normalized.cipherAlg,
          ...(this.normalized.ivLength === undefined
            ? {}
            : { ivLength: this.normalized.ivLength }),
          ...(this.normalized.tagLength === undefined
            ? {}
            : { tagLength: this.normalized.tagLength }),
          ...(this.normalized.counterLength === undefined
            ? {}
            : { counterLength: this.normalized.counterLength }),
          use: 'enc',
          key_ops: [],
        }),
        this.strategy.importAlgorithm,
        false,
        this.strategy.publicKeyUsages
      )

      const sharedCryptoKey = await crypto.subtle.deriveKey(
        {
          name: this.strategy.deriveAlgorithmName,
          public: publicKey,
        } as AlgorithmIdentifier,
        privateKey,
        sharedCipher.keyAlgorithm,
        true,
        sharedCipher.keyUsages
      )

      return {
        cipherJwk: sharedCipher.normalize(
          await crypto.subtle.exportKey('jwk', sharedCryptoKey)
        ),
      }
    } catch {
      throw new CryptosuiteError(
        'DECAPSULATION_FAILED',
        'DecapsulateKeyHarness.decapsulate: failed to derive the cipher JWK.'
      )
    }
  }
}
