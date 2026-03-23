import { CryptosuiteError } from '../../../.errors/class.js'
import { resolveDigitalSignatureAlgorithm } from '../../resolveDigitalSignatureAlgorithm/index.js'
import type { VerifyJWK } from '../types/index.js'

export function normalizeVerifyJWK(jwk: JsonWebKey): VerifyJWK {
  const candidate = jwk as JsonWebKey | null
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

  resolveDigitalSignatureAlgorithm(candidate)

  return {
    ...jwk,
    use: 'sig',
    key_ops: ['verify'] as const,
  } as VerifyJWK
}
