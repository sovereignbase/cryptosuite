type NoSymmetric = {
  k?: never
}

type NoPrivate = {
  d?: never
  p?: never
  q?: never
  dp?: never
  dq?: never
  qi?: never
  oth?: never
}

type MLKEM1024EncapsulateKey = JsonWebKey &
  NoSymmetric &
  NoPrivate & {
    kty: 'AKP'
    alg: 'ML-KEM-1024'
    x: string
    use: 'enc'
    key_ops: readonly []
  }

type MLKEM1024DecapsulateKey = JsonWebKey &
  NoSymmetric & {
    kty: 'AKP'
    alg: 'ML-KEM-1024'
    d: string
    use: 'enc'
    key_ops: readonly ('deriveKey' | 'deriveBits')[]
  }

type MLKEM1024KeyOffer = {
  ciphertext: ArrayBuffer
}

type MLKEM1024EncapsulateParams = {
  publicKey: Uint8Array
}

type MLKEM1024DecapsulateParams = {
  secretKey: Uint8Array
}

export type EncapsulateKey = MLKEM1024EncapsulateKey

export type DecapsulateKey = MLKEM1024DecapsulateKey

export type KeyOffer = MLKEM1024KeyOffer

export type KeyAgreementParams =
  | MLKEM1024EncapsulateParams
  | MLKEM1024DecapsulateParams
