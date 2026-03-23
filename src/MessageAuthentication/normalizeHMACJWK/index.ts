import { fromBase64UrlString } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import type { HMACJWK } from '../types/index.js'

export function normalizeHMACJWK(jwk: JsonWebKey): HMACJWK {
  const candidate = jwk as HMACJWK | null
  if (
    !candidate ||
    typeof candidate !== 'object' ||
    candidate.kty !== 'oct' ||
    typeof candidate.k !== 'string'
  ) {
    throw new CryptosuiteError(
      'HMAC_JWK_INVALID',
      'normalizeHMACJWK: expected a symmetric HMAC JWK.'
    )
  }

  if (candidate.use !== undefined && candidate.use !== 'sig') {
    throw new CryptosuiteError(
      'HMAC_JWK_INVALID',
      'normalizeHMACJWK: JWK.use must be "sig" when present.'
    )
  }

  if (candidate.key_ops !== undefined) {
    if (
      !Array.isArray(candidate.key_ops) ||
      candidate.key_ops.some((operation) => {
        return operation !== 'sign' && operation !== 'verify'
      })
    ) {
      throw new CryptosuiteError(
        'HMAC_JWK_INVALID',
        'normalizeHMACJWK: JWK.key_ops must only contain sign/verify.'
      )
    }
  }

  try {
    fromBase64UrlString(candidate.k)
  } catch {
    throw new CryptosuiteError(
      'BASE64URL_INVALID',
      'normalizeHMACJWK: invalid base64url key material.'
    )
  }

  const normalizedHash =
    candidate.hash ??
    (candidate.alg === 'HS1'
      ? 'SHA-1'
      : candidate.alg === 'HS256'
        ? 'SHA-256'
        : candidate.alg === 'HS384'
          ? 'SHA-384'
          : candidate.alg === 'HS512'
            ? 'SHA-512'
            : undefined)

  if (normalizedHash === undefined) {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'normalizeHMACJWK: unsupported HMAC JWK alg.'
    )
  }

  return {
    ...candidate,
    alg:
      candidate.alg ??
      (normalizedHash === 'SHA-1' ? 'HS1' : `HS${normalizedHash.slice(4)}`),
    use: 'sig',
    key_ops:
      candidate.key_ops === undefined
        ? (['sign', 'verify'] as const)
        : [...candidate.key_ops],
    hash: normalizedHash,
  }
}
