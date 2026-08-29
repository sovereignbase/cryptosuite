/** @inline */
type NoSymmetric = {
  k?: never
}

/** @inline */
type NoPrivate = {
  d?: never
  p?: never
  q?: never
  dp?: never
  dq?: never
  qi?: never
  oth?: never
}

/** @inline */
type MlKem1024EncapsulateKey = JsonWebKey &
  NoSymmetric &
  NoPrivate & {
    kty: 'AKP'
    alg: 'ML-KEM-1024'
    x: string
    use: 'enc'
    key_ops: readonly []
  }

/** @inline */
type HybridEncapsulateKey = JsonWebKey &
  NoSymmetric &
  NoPrivate & {
    kty: 'AKP'
    alg: 'X25519-ML-KEM-768'
    x: string
    use: 'enc'
    key_ops: readonly []
  }

/** @inline */
type MlKem1024DecapsulateKey = JsonWebKey &
  NoSymmetric & {
    kty: 'AKP'
    alg: 'ML-KEM-1024'
    d: string
    use: 'enc'
    key_ops: readonly ('deriveKey' | 'deriveBits')[]
  }

/** @inline */
type HybridDecapsulateKey = JsonWebKey &
  NoSymmetric & {
    kty: 'AKP'
    alg: 'X25519-ML-KEM-768'
    d: string
    use: 'enc'
    key_ops: readonly ('deriveKey' | 'deriveBits')[]
  }

/** @inline */
type KeyAgreementOffer = {
  /** The encapsulated shared-secret artifact emitted by a supported key agreement algorithm. */
  ciphertext: Uint8Array
}

type EncapsulateParams = {
  /** The raw supported key agreement public key bytes. */
  publicKey: Uint8Array
}

type DecapsulateParams = {
  /** The raw supported key agreement private key bytes. */
  secretKey: Uint8Array
}

/**
 * Public supported key agreement JWK used to encapsulate a shared cipher key.
 *
 * @expand
 */
export type EncapsulateKey = MlKem1024EncapsulateKey | HybridEncapsulateKey

/**
 * Private supported key agreement JWK used to decapsulate a shared cipher key.
 *
 * @expand
 */
export type DecapsulateKey = MlKem1024DecapsulateKey | HybridDecapsulateKey

/**
 * Encapsulated key agreement artifact exchanged with the counterparty.
 */
export type KeyOffer = KeyAgreementOffer

/**
 * Runtime key agreement parameters used internally by key agreement harnesses.
 */
export type KeyAgreementParams = EncapsulateParams | DecapsulateParams
