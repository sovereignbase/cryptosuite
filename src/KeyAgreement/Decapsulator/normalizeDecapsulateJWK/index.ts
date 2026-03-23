import { DecapsulateJWK } from '../types/index.js'

export function normalizeDecapsulateJWK(jwk: JsonWebKey): DecapsulateJWK {
  const a = jwk as any

  if (!a || typeof a !== 'object') {
    throw new TypeError('JWK must be an object')
  }

  if (typeof a.kty !== 'string' || !a.kty) {
    throw new TypeError('JWK.kty required')
  }

  if (typeof a.alg !== 'string' || !a.alg) {
    throw new TypeError('JWK.alg required')
  }

  // Asymmetric private only (must have private scalar/exponent, no symmetric key material)
  if (typeof a.d !== 'string' || !a.d || 'k' in a) {
    throw new TypeError('Not an asymmetric private unwrap JWK')
  }

  if (a.use !== undefined && a.use !== 'enc') {
    throw new TypeError('JWK.use must be "enc" if present')
  }

  if (a.key_ops !== undefined) {
    if (!Array.isArray(a.key_ops) || !a.key_ops.includes('unwrapKey')) {
      throw new TypeError('JWK.key_ops must include "unwrapKey" if present')
    }
  }

  return {
    ...jwk,
    use: 'enc',
    key_ops: ['unwrapKey'] as const,
  } as DecapsulateJWK
}
