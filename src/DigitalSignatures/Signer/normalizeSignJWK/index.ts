import { SignJWK } from '../types/index.js'

export function normalizeSignJWK(jwk: JsonWebKey): SignJWK {
  const a = jwk as any
  if (!a || typeof a !== 'object') throw new TypeError('JWK must be an object')
  if (typeof a.kty !== 'string' || !a.kty)
    throw new TypeError('JWK.kty required')

  if (typeof a.alg !== 'string' || !a.alg)
    throw new TypeError('JWK.alg required')

  if (typeof a.d !== 'string' || !a.d || 'k' in a) {
    throw new TypeError('Not an asymmetric private sign JWK')
  }

  if (a.use !== undefined && a.use !== 'sig') {
    throw new TypeError('JWK.use must be "sig" if present')
  }
  if (a.key_ops !== undefined) {
    if (!Array.isArray(a.key_ops) || !a.key_ops.includes('sign')) {
      throw new TypeError('JWK.key_ops must include "sign" if present')
    }
  }

  return {
    ...jwk,
    use: 'sig',
    key_ops: ['sign'] as const,
  } as SignJWK
}
