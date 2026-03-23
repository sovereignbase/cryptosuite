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

export type CipherJWK = JsonWebKey &
  NoAsymmetric & {
    kty: 'oct'
    k: string
    alg: string
    use?: 'enc'
    key_ops?: readonly ('encrypt' | 'decrypt')[]
  }
