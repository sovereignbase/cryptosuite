import { CryptosuiteError } from '../../../.errors/class.js'
import { resolveDigitalSignatureAlgorithm } from '../../resolveDigitalSignatureAlgorithm/index.js'
import type { SignJWK } from '../types/index.js'

export function normalizeSignJWK(jwk: JsonWebKey): SignJWK {
  const candidate = jwk as JsonWebKey | null

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

  resolveDigitalSignatureAlgorithm(candidate)

  return {
    ...jwk,
    use: 'sig',
    key_ops: ['sign'] as const,
  } as SignJWK
}
