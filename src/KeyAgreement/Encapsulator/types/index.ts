type NoPrivate = {
  d?: never
  p?: never
  q?: never
  dp?: never
  dq?: never
  qi?: never
  oth?: never
  k?: never
}

export type EncapsulateJWK = JsonWebKey &
  NoPrivate & {
    kty: string
    alg: string
    use?: 'enc'
    key_ops?: readonly ('wrapKey')[]
      | readonly ('deriveKey' | 'deriveBits')[]
      | readonly []
  }
