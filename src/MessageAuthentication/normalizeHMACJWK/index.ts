import { assertHmacSha256Key } from '../../.helpers/assertHmacSha256Key.js'
import type { HMACJWK } from '../index.js'

export function normalizeHMACJWK(jwk: JsonWebKey): HMACJWK {
  assertHmacSha256Key(jwk, 'normalizeHMACJWK')
  return {
    ...jwk,
    alg: 'HS256',
    use: 'sig',
    key_ops: ['sign', 'verify'] as const,
  }
}
