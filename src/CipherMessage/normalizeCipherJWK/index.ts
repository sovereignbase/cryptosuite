import { fromBase64UrlString } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import type { CipherJWK } from '../types/index.js'

export function normalizeCipherJWK(jwk: JsonWebKey): CipherJWK {
  const candidate = jwk as CipherJWK | null

  if (
    !candidate ||
    typeof candidate !== 'object' ||
    candidate.kty !== 'oct' ||
    typeof candidate.k !== 'string'
  ) {
    throw new CryptosuiteError(
      'CIPHER_JWK_INVALID',
      'normalizeCipherJWK: expected a symmetric cipher JWK.'
    )
  }

  if (candidate.use !== undefined && candidate.use !== 'enc') {
    throw new CryptosuiteError(
      'CIPHER_JWK_INVALID',
      'normalizeCipherJWK: JWK.use must be "enc" when present.'
    )
  }

  if (candidate.key_ops !== undefined) {
    if (
      !Array.isArray(candidate.key_ops) ||
      candidate.key_ops.some((operation) => {
        return operation !== 'encrypt' && operation !== 'decrypt'
      })
    ) {
      throw new CryptosuiteError(
        'CIPHER_JWK_INVALID',
        'normalizeCipherJWK: JWK.key_ops must only contain encrypt/decrypt.'
      )
    }
  }

  let keyBytes: Uint8Array
  try {
    keyBytes = fromBase64UrlString(candidate.k)
  } catch {
    throw new CryptosuiteError(
      'BASE64URL_INVALID',
      'normalizeCipherJWK: invalid base64url key material.'
    )
  }

  if (typeof candidate.alg !== 'string' || !candidate.alg) {
    throw new CryptosuiteError(
      'CIPHER_JWK_INVALID',
      'normalizeCipherJWK: JWK.alg is required.'
    )
  }

  const match = /^A(?<length>\d+)(?<mode>GCM|CBC|CTR)$/.exec(candidate.alg)
  if (!match?.groups) {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'normalizeCipherJWK: unsupported cipher JWK alg.'
    )
  }

  const algorithmLength = Number(match.groups.length)
  if (!Number.isFinite(algorithmLength) || keyBytes.byteLength * 8 !== algorithmLength) {
    throw new CryptosuiteError(
      'CIPHER_JWK_INVALID',
      'normalizeCipherJWK: key material length does not match JWK.alg.'
    )
  }

  return {
    ...candidate,
    use: 'enc',
    key_ops:
      candidate.key_ops === undefined
        ? (['encrypt', 'decrypt'] as const)
        : [...candidate.key_ops],
    ivLength:
      candidate.ivLength ??
      (match.groups.mode === 'GCM' ? 12 : match.groups.mode === 'CBC' ? 16 : 16),
    tagLength:
      match.groups.mode === 'GCM' ? (candidate.tagLength ?? 128) : undefined,
    counterLength:
      match.groups.mode === 'CTR' ? (candidate.counterLength ?? 64) : undefined,
  }
}
