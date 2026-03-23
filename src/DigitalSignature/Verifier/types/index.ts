type NoPrivate = {
  d?: never
  p?: never
  q?: never
  dp?: never
  dq?: never
  qi?: never
  k?: never
}

export type VerifyJWK = JsonWebKey &
  NoPrivate & {
    kty: string
    alg: string
    hash?: string
    saltLength?: number
    use?: 'sig'
    key_ops?: readonly 'verify'[]
  }
