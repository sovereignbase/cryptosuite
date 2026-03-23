type NoSymmetric = {
  k?: never
}

export type DecapsulateJWK = JsonWebKey &
  NoSymmetric & {
    kty: string
    alg: string
    use?: 'enc'
    key_ops?: readonly 'unwrapKey'[]
  }
