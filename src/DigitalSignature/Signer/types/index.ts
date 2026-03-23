type NoSymmetric = {
  k?: never
}

type HasPrivate = {
  d: string
}

export type SignJWK = JsonWebKey &
  NoSymmetric &
  HasPrivate & {
    kty: string
    alg: string
    use?: 'sig'
    key_ops?: readonly 'sign'[]
  }
