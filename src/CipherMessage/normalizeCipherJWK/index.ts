import { assertAesGcm256Key } from '../../.helpers/assertAesGcm256Key.js'
import type { CipherJWK } from '../types/index.js'

export function normalizeCipherJWK(jwk: JsonWebKey): CipherJWK {
  assertAesGcm256Key(jwk, 'normalizeCipherJWK')
  return {
    ...jwk,
    alg: 'A256GCM',
    use: 'enc',
    key_ops: ['encrypt', 'decrypt'] as const,
  } as CipherJWK
}
