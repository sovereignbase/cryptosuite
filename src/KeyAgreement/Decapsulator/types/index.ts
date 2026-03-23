type NoSymmetric = {
  k?: never
}

export type DecapsulateJWK = JsonWebKey &
  NoSymmetric & {
    kty: string
    alg: string
    cipherAlg: string
    hash?: string
    ivLength?: number
    tagLength?: number
    counterLength?: number
    use?: 'enc'
    key_ops?: readonly ('unwrapKey' | 'deriveKey' | 'deriveBits')[]
  }
