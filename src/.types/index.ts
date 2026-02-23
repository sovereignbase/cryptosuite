type NoPrivate = {
  // common private
  d?: never

  // RSA private parts
  p?: never
  q?: never
  dp?: never
  dq?: never
  qi?: never

  // symmetric JWK ("oct") uses `k` -> block it => asymmetric-only
  k?: never
}

export type VerifyJWK = JsonWebKey &
  NoPrivate & {
    // require kty, but keep it open for future PQC key types
    kty: string

    // optional metadata (not required by WebCrypto, but useful)
    use?: 'sig'
    key_ops?: readonly 'verify'[]
  }
