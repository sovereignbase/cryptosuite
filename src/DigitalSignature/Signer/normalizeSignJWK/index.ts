import { CryptosuiteError } from '../../../.errors/class.js'
import type { SignJWK } from '../types/index.js'

function hashOf(alg: string): string | undefined {
  if (alg === 'ES256' || alg === 'PS256' || alg === 'RS256') return 'SHA-256'
  if (alg === 'ES384' || alg === 'PS384' || alg === 'RS384') return 'SHA-384'
  if (alg === 'ES512' || alg === 'PS512' || alg === 'RS512') return 'SHA-512'
  return undefined
}

function digestLengthOf(hash: string): number | undefined {
  if (hash === 'SHA-1') return 20
  if (hash === 'SHA-256') return 32
  if (hash === 'SHA-384') return 48
  if (hash === 'SHA-512') return 64
  return undefined
}

export function normalizeSignJWK(jwk: JsonWebKey): SignJWK {
  const candidate = jwk as (JsonWebKey & {
    hash?: string
    saltLength?: number
  }) | null

  if (!candidate || typeof candidate !== 'object') {
    throw new CryptosuiteError(
      'SIGN_JWK_INVALID',
      'normalizeSignJWK: expected an asymmetric private signature JWK.'
    )
  }

  if (typeof candidate.d !== 'string' || typeof candidate.alg !== 'string') {
    throw new CryptosuiteError(
      'SIGN_JWK_INVALID',
      'normalizeSignJWK: missing required private JWK fields.'
    )
  }

  if (candidate.use !== undefined && candidate.use !== 'sig') {
    throw new CryptosuiteError(
      'SIGN_JWK_INVALID',
      'normalizeSignJWK: JWK.use must be "sig" when present.'
    )
  }

  if (candidate.key_ops !== undefined) {
    if (
      !Array.isArray(candidate.key_ops) ||
      candidate.key_ops.length !== 1 ||
      candidate.key_ops[0] !== 'sign'
    ) {
      throw new CryptosuiteError(
        'SIGN_JWK_INVALID',
        'normalizeSignJWK: JWK.key_ops must be ["sign"] when present.'
      )
    }
  }

  if (candidate.kty === 'OKP') {
    if (candidate.crv !== 'Ed25519' && candidate.crv !== 'Ed448') {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'normalizeSignJWK: unsupported OKP signature curve.'
      )
    }

    if (candidate.alg !== 'EdDSA' && candidate.alg !== candidate.crv) {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'normalizeSignJWK: unsupported OKP signature JWK alg.'
      )
    }

    return {
      ...candidate,
      use: 'sig',
      key_ops: ['sign'] as const,
    }
  }

  if (candidate.kty === 'EC') {
    if (typeof candidate.crv !== 'string') {
      throw new CryptosuiteError(
        'SIGN_JWK_INVALID',
        'normalizeSignJWK: EC signature JWK.crv is required.'
      )
    }

    const hash = candidate.hash ?? hashOf(candidate.alg)
    if ((candidate.alg !== 'ECDSA' && hash === undefined) || typeof hash !== 'string') {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'normalizeSignJWK: unsupported ECDSA signature JWK alg.'
      )
    }

    return {
      ...candidate,
      use: 'sig',
      key_ops: ['sign'] as const,
      hash,
    } as SignJWK
  }

  if (candidate.kty === 'RSA') {
    const isPss =
      candidate.alg === 'RSA-PSS' || /^PS\d+$/.test(candidate.alg)
    const isPkcs1 =
      candidate.alg === 'RSASSA-PKCS1-v1_5' || /^RS\d+$/.test(candidate.alg)
    const hash = candidate.hash ?? hashOf(candidate.alg)

    if ((!isPss && !isPkcs1) || typeof hash !== 'string') {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'normalizeSignJWK: unsupported RSA signature JWK alg.'
      )
    }

    return {
      ...candidate,
      use: 'sig',
      key_ops: ['sign'] as const,
      hash,
      saltLength:
        isPss && candidate.saltLength === undefined
          ? digestLengthOf(hash)
          : candidate.saltLength,
    } as SignJWK
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    'normalizeSignJWK: unsupported signature JWK kty.'
  )
}
