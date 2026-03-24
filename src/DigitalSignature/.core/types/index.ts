type NoPrivate = {
  d?: never
  p?: never
  q?: never
  dp?: never
  dq?: never
  qi?: never
  k?: never
}

type MLDSA87VerifyKey = JsonWebKey &
  NoPrivate & {
    kty: 'AKP'
    alg: 'ML-DSA-87'
    x: string
    use: 'sig'
    key_ops: readonly 'verify'[]
  }

type NoSymmetric = {
  k?: never
}

type HasPrivate = {
  d: string
}

type MLDSA87SignKey = JsonWebKey &
  NoSymmetric &
  HasPrivate & {
    kty: 'AKP'
    alg: 'ML-DSA-87'
    use: 'sig'
    key_ops: readonly 'sign'[]
  }

type MLDSA87VerifyParams = {
  publicKey: Uint8Array
}

type MLDSA87SignParams = {
  secretKey: Uint8Array
}

export type VerifyKey = MLDSA87VerifyKey

export type SignKey = MLDSA87SignKey

export type DigitalSignatureParams = MLDSA87VerifyParams | MLDSA87SignParams
