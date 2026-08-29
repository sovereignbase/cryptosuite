type NoAsymmetric = {
  d?: never
  p?: never
  q?: never
  dp?: never
  dq?: never
  qi?: never
  oth?: never
  n?: never
  e?: never
  x?: never
  y?: never
  crv?: never
}

type HS256Key = JsonWebKey &
  NoAsymmetric & {
    kty: 'oct'
    k: string
    alg: 'HS256'
    use: 'sig'
    key_ops: readonly ('sign' | 'verify')[]
  }

type HMACParams = Record<never, never>

/**
 * Symmetric HMAC-SHA-256 JWK used for message authentication operations.
 */
export type MessageAuthenticationKey = HS256Key

/**
 * Algorithm parameters for message authentication operations.
 *
 * HMAC does not currently require serialized per-message parameters.
 */
export type MessageAuthenticationParams = HMACParams
