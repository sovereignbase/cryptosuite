import { CryptosuiteError } from '../../../.errors/class.js'
import type { EncapsulateJWK } from '../types/index.js'

function hashOf(alg: string): string | undefined {
  if (alg === 'RSA-OAEP') return 'SHA-1'
  if (alg === 'RSA-OAEP-256') return 'SHA-256'
  if (alg === 'RSA-OAEP-384') return 'SHA-384'
  if (alg === 'RSA-OAEP-512') return 'SHA-512'
  return undefined
}

function isEcdhAlg(alg: string): boolean {
  return alg === 'ECDH' || alg.startsWith('ECDH-ES')
}

function assertCipherDeclaration(
  candidate: {
    cipherAlg?: string
    tagLength?: number
    counterLength?: number
  },
  operation: string
): void {
  if (typeof candidate.cipherAlg !== 'string') {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID',
      `${operation}: JWK.cipherAlg is required.`
    )
  }

  const match = /^A(?<length>\d+)(?<mode>GCM|CBC|CTR)$/.exec(candidate.cipherAlg)
  if (!match?.groups) {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      `${operation}: unsupported cipher declaration.`
    )
  }

  if (candidate.tagLength !== undefined && match.groups.mode !== 'GCM') {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID',
      `${operation}: JWK.tagLength is only valid for GCM cipher declarations.`
    )
  }

  if (candidate.counterLength !== undefined && match.groups.mode !== 'CTR') {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID',
      `${operation}: JWK.counterLength is only valid for CTR cipher declarations.`
    )
  }
}

export function normalizeEncapsulateJWK(jwk: JsonWebKey): EncapsulateJWK {
  const candidate = jwk as (JsonWebKey & {
    hash?: string
    cipherAlg?: string
    ivLength?: number
    tagLength?: number
    counterLength?: number
  }) | null

  if (!candidate || typeof candidate !== 'object') {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID',
      'normalizeEncapsulateJWK: expected an asymmetric public key agreement JWK.'
    )
  }

  if (
    typeof candidate.kty !== 'string' ||
    typeof candidate.alg !== 'string' ||
    'd' in candidate ||
    'p' in candidate ||
    'q' in candidate ||
    'dp' in candidate ||
    'dq' in candidate ||
    'qi' in candidate ||
    'oth' in candidate ||
    'k' in candidate
  ) {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID',
      'normalizeEncapsulateJWK: expected an asymmetric public key agreement JWK.'
    )
  }

  if (candidate.use !== undefined && candidate.use !== 'enc') {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID',
      'normalizeEncapsulateJWK: JWK.use must be "enc" when present.'
    )
  }

  const isWrap =
    candidate.kty === 'RSA' &&
    (candidate.alg === 'RSA-OAEP' ||
      candidate.alg === 'RSA-OAEP-256' ||
      candidate.alg === 'RSA-OAEP-384' ||
      candidate.alg === 'RSA-OAEP-512')
  const isDerive =
    (candidate.kty === 'EC' &&
      typeof candidate.crv === 'string' &&
      isEcdhAlg(candidate.alg)) ||
    (candidate.kty === 'OKP' &&
      (candidate.crv === 'X25519' || candidate.crv === 'X448') &&
      (candidate.alg === candidate.crv || isEcdhAlg(candidate.alg)))

  if (!isWrap && !isDerive) {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'normalizeEncapsulateJWK: unsupported key agreement JWK alg.'
    )
  }

  assertCipherDeclaration(candidate, 'normalizeEncapsulateJWK')

  if (candidate.key_ops !== undefined) {
    if (!Array.isArray(candidate.key_ops)) {
      throw new CryptosuiteError(
        'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID',
        'normalizeEncapsulateJWK: JWK.key_ops must be an array when present.'
      )
    }

    if (isWrap) {
      if (candidate.key_ops.length !== 1 || candidate.key_ops[0] !== 'wrapKey') {
        throw new CryptosuiteError(
          'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID',
          'normalizeEncapsulateJWK: RSA encapsulation JWK.key_ops must be ["wrapKey"] when present.'
        )
      }
    } else if (candidate.key_ops.length !== 0) {
      throw new CryptosuiteError(
        'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID',
        'normalizeEncapsulateJWK: derived key agreement public JWK.key_ops must be [] when present.'
      )
    }
  }

  if (isWrap && typeof (candidate.hash ?? hashOf(candidate.alg)) !== 'string') {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'normalizeEncapsulateJWK: unsupported RSA-OAEP JWK alg.'
    )
  }

  return {
    ...candidate,
    use: 'enc',
    key_ops: isWrap ? (['wrapKey'] as const) : ([] as const),
    ...(isWrap
      ? { hash: candidate.hash ?? hashOf(candidate.alg) }
      : {}),
  } as EncapsulateJWK
}
