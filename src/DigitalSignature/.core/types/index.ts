/** @inline */
type NoPrivate = {
  d?: never
  p?: never
  q?: never
  dp?: never
  dq?: never
  qi?: never
  k?: never
}

/** @inline */
type MlDsa87VerifyKey = JsonWebKey &
  NoPrivate & {
    kty: 'AKP'
    alg: 'ML-DSA-87'
    x: string
    use: 'sig'
    key_ops: readonly 'verify'[]
  }

/** @inline */
type HybridVerifyKey = JsonWebKey &
  NoPrivate & {
    kty: 'AKP'
    alg: 'Ed25519-ML-DSA-65'
    x: string
    use: 'sig'
    key_ops: readonly 'verify'[]
  }

/** @inline */
type NoSymmetric = {
  k?: never
}

/** @inline */
type HasPrivate = {
  d: string
}

/** @inline */
type MlDsa87SignKey = JsonWebKey &
  NoSymmetric &
  HasPrivate & {
    kty: 'AKP'
    alg: 'ML-DSA-87'
    use: 'sig'
    key_ops: readonly 'sign'[]
  }

/** @inline */
type HybridSignKey = JsonWebKey &
  NoSymmetric &
  HasPrivate & {
    kty: 'AKP'
    alg: 'Ed25519-ML-DSA-65'
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
 *
 * @expand
 */
export type VerifyKey = MlDsa87VerifyKey | HybridVerifyKey

/**
 * Private supported digital signature JWK used to produce signatures.
 *
 * @expand
 */
export type SignKey = MlDsa87SignKey | HybridSignKey

/**
 * Runtime key material used internally by signing and verification harnesses.
 */
export type DigitalSignatureParams = VerifyParams | SignParams
