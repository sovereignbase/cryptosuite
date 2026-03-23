import { CipherJWK } from '../types/index.js'

export function normalizeCipherJWK(jwk: JsonWebKey): CipherJWK {
  const a = jwk as any

  if (!a || typeof a !== 'object') throw new TypeError('JWK must be an object')

  if (a.kty !== 'oct') {
    throw new TypeError('JWK.kty must be "oct"')
  }

  if (typeof a.k !== 'string' || !a.k) {
    throw new TypeError('JWK.k required')
  }

  if (typeof a.alg !== 'string' || !a.alg) {
    throw new TypeError('JWK.alg required')
  }

  if (
    'd' in a ||
    'p' in a ||
    'q' in a ||
    'dp' in a ||
    'dq' in a ||
    'qi' in a ||
    'oth' in a ||
    'n' in a ||
    'e' in a ||
    'x' in a ||
    'y' in a ||
    'crv' in a
  ) {
    throw new TypeError('Not a symmetric cipher JWK')
  }

  if (a.use !== undefined && a.use !== 'enc') {
    throw new TypeError('JWK.use must be "enc" if present')
  }

  if (a.key_ops !== undefined) {
    if (
      !Array.isArray(a.key_ops) ||
      (!a.key_ops.includes('encrypt') && !a.key_ops.includes('decrypt'))
    ) {
      throw new TypeError(
        'JWK.key_ops must include "encrypt" or "decrypt" if present'
      )
    }
  }

  return {
    ...jwk,
    use: 'enc',
    ...(a.key_ops !== undefined
      ? {}
      : { key_ops: ['encrypt', 'decrypt'] as const }),
  } as CipherJWK
}
