import { CryptosuiteError } from '../../../.errors/class.js'
import type { VerifyJWK } from '../types/index.js'

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

export function normalizeVerifyJWK(jwk: JsonWebKey): VerifyJWK {
  const candidate = jwk as (JsonWebKey & {
    hash?: string
    saltLength?: number
  }) | null
  if (
    !candidate ||
    typeof candidate !== 'object' ||
    typeof candidate.alg !== 'string' ||
    'd' in candidate ||
    'p' in candidate ||
    'q' in candidate ||
    'dp' in candidate ||
    'dq' in candidate ||
    'qi' in candidate ||
    'k' in candidate
  ) {
    throw new CryptosuiteError(
      'VERIFY_JWK_INVALID',
      'normalizeVerifyJWK: expected an asymmetric public signature JWK.'
    )
  }

  if (candidate.use !== undefined && candidate.use !== 'sig') {
    throw new CryptosuiteError(
      'VERIFY_JWK_INVALID',
      'normalizeVerifyJWK: JWK.use must be "sig" when present.'
    )
  }

  if (candidate.key_ops !== undefined) {
    if (
      !Array.isArray(candidate.key_ops) ||
      candidate.key_ops.length !== 1 ||
      candidate.key_ops[0] !== 'verify'
    ) {
      throw new CryptosuiteError(
        'VERIFY_JWK_INVALID',
        'normalizeVerifyJWK: JWK.key_ops must be ["verify"] when present.'
      )
    }
  }

  if (candidate.kty === 'OKP') {
    if (candidate.crv !== 'Ed25519' && candidate.crv !== 'Ed448') {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'normalizeVerifyJWK: unsupported OKP signature curve.'
      )
    }

    if (candidate.alg !== 'EdDSA' && candidate.alg !== candidate.crv) {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'normalizeVerifyJWK: unsupported OKP signature JWK alg.'
      )
    }

    return {
      ...candidate,
      use: 'sig',
      key_ops: ['verify'] as const,
    }
  }

  if (candidate.kty === 'EC') {
    if (typeof candidate.crv !== 'string') {
      throw new CryptosuiteError(
        'VERIFY_JWK_INVALID',
        'normalizeVerifyJWK: EC signature JWK.crv is required.'
      )
    }

    const hash = candidate.hash ?? hashOf(candidate.alg)
    if ((candidate.alg !== 'ECDSA' && hash === undefined) || typeof hash !== 'string') {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'normalizeVerifyJWK: unsupported ECDSA signature JWK alg.'
      )
    }

    return {
      ...candidate,
      use: 'sig',
      key_ops: ['verify'] as const,
      hash,
    } as VerifyJWK
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
        'normalizeVerifyJWK: unsupported RSA signature JWK alg.'
      )
    }

    return {
      ...candidate,
      use: 'sig',
      key_ops: ['verify'] as const,
      hash,
      saltLength:
        isPss && candidate.saltLength === undefined
          ? digestLengthOf(hash)
          : candidate.saltLength,
    } as VerifyJWK
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    'normalizeVerifyJWK: unsupported signature JWK kty.'
  )
}
