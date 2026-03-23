import { EncapsulateJWK } from '../types/index.js'

export function normalizeEncapsulateJWK(jwk: JsonWebKey): EncapsulateJWK {
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

  // Public asymmetric only (no private parts, no symmetric key material)
  if (
    'd' in a ||
    'p' in a ||
    'q' in a ||
    'dp' in a ||
    'dq' in a ||
    'qi' in a ||
    'oth' in a ||
    'k' in a
  ) {
    throw new TypeError('Not an asymmetric public wrap JWK')
  }

  if (a.use !== undefined && a.use !== 'enc') {
    throw new TypeError('JWK.use must be "enc" if present')
  }

  if (a.key_ops !== undefined) {
    if (!Array.isArray(a.key_ops) || !a.key_ops.includes('wrapKey')) {
      throw new TypeError('JWK.key_ops must include "wrapKey" if present')
    }
  }

  return {
    ...jwk,
    use: 'enc',
    key_ops: ['wrapKey'] as const,
  } as EncapsulateJWK
}
