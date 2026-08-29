type NoPrivate = {
  d?: never
  p?: never
  q?: never
  dp?: never
  dq?: never
  qi?: never
  k?: never
}

type DigitalSignatureAlg = 'ML-DSA-87' | 'Ed25519-ML-DSA-65'

type VerifyKeyByAlg<Alg extends DigitalSignatureAlg> = JsonWebKey &
  NoPrivate & {
    kty: 'AKP'
    alg: Alg
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

type SignKeyByAlg<Alg extends DigitalSignatureAlg> = JsonWebKey &
  NoSymmetric &
  HasPrivate & {
    kty: 'AKP'
    alg: Alg
    use: 'sig'
    key_ops: readonly 'sign'[]
  }

type VerifyParams = {
  /** The raw supported digital signature public key bytes. */
  publicKey: Uint8Array
}

type SignParams = {
  /** The raw supported digital signature private key bytes. */
  secretKey: Uint8Array
}

/**
 * Public supported digital signature JWK used to verify signatures.
 */
export type VerifyKey =
  VerifyKeyByAlg<'ML-DSA-87'> | VerifyKeyByAlg<'Ed25519-ML-DSA-65'>

/**
 * Private supported digital signature JWK used to produce signatures.
 */
export type SignKey =
  SignKeyByAlg<'ML-DSA-87'> | SignKeyByAlg<'Ed25519-ML-DSA-65'>

/**
 * Runtime key material used internally by signing and verification harnesses.
 */
export type DigitalSignatureParams = VerifyParams | SignParams
