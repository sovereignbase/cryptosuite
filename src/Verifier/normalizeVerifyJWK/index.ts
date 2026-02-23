import { VerifyJWK } from '../types/index.js'

export function normalizeVerifyJWK(jwk: JsonWebKey): VerifyJWK {
  const a = jwk as any
  if (!a || typeof a !== 'object') throw new TypeError('JWK must be an object')
  if (typeof a.kty !== 'string' || !a.kty)
    throw new TypeError('JWK.kty required')

  if (typeof a.alg !== 'string' || !a.alg)
    throw new TypeError('JWK.alg required')

  if (
    'd' in a ||
    'p' in a ||
    'q' in a ||
    'dp' in a ||
    'dq' in a ||
    'qi' in a ||
    'k' in a
  ) {
    throw new TypeError('Not an asymmetric public verify JWK')
  }

  if (a.use !== undefined && a.use !== 'sig') {
    throw new TypeError('JWK.use must be "sig" if present')
  }
  if (a.key_ops !== undefined) {
    if (!Array.isArray(a.key_ops) || !a.key_ops.includes('verify')) {
      throw new TypeError('JWK.key_ops must include "verify" if present')
    }
  }

  return {
    ...jwk,
    use: 'sig',
    key_ops: ['verify'] as const,
  } as VerifyJWK
}
