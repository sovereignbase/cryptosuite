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
    ivLength?: number
    tagLength?: number
    counterLength?: number
  }

export type CipherMessageAlgorithm =
  | {
      name: 'AES-GCM'
      length: number
      alg?: string
      ivLength?: number
      tagLength?: number
    }
  | {
      name: 'AES-CBC'
      length: number
      alg?: string
      ivLength?: number
    }
  | {
      name: 'AES-CTR'
      length: number
      alg?: string
      counterLength?: number
    }

export type CipherMessageArtifact = {
  ciphertext: ArrayBuffer
  params: AesGcmParams | AesCbcParams | AesCtrParams
}
