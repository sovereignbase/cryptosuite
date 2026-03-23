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

type A256CTRKey = JsonWebKey &
  NoAsymmetric & {
    kty: 'oct'
    k: string
    alg: 'A256CTR'
    use: 'enc'
    key_ops: readonly ('encrypt' | 'decrypt')[]
  }

export type A256CTRParams = {
  iv: Uint8Array
}

type A256CTRMessage = {
  ciphertext: ArrayBuffer
} & A256CTRParams

export type CipherKey = A256CTRKey

export type CipherParams = A256CTRParams

export type CipherMessage = A256CTRMessage
