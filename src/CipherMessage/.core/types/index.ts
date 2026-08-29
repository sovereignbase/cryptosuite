/** @inline */
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

/** @inline */
type A256CTRKey = JsonWebKey &
  NoAsymmetric & {
    kty: 'oct'
    k: string
    alg: 'A256CTR'
    use: 'enc'
    key_ops: readonly ('encrypt' | 'decrypt')[]
  }

/** @inline */
type A256GCMKey = JsonWebKey &
  NoAsymmetric & {
    kty: 'oct'
    k: string
    alg: 'A256GCM'
    use: 'enc'
    key_ops: readonly ('encrypt' | 'decrypt')[]
  }

/**
 * Algorithm parameters serialized alongside an AES-CTR cipher message.
 *
 * @inline
 */
export type A256CTRParams = {
  /** The 96-bit initialization vector used for encryption. */
  iv: Uint8Array
}

/**
 * Algorithm parameters serialized alongside an AES-GCM cipher message.
 *
 * @inline
 */
export type A256GCMParams = {
  /** The 96-bit initialization vector used for encryption. */
  iv: Uint8Array
}

/** @inline */
type A256CTRMessage = {
  /** The encrypted payload bytes. */
  ciphertext: Uint8Array
} & A256CTRParams

/** @inline */
type A256GCMMessage = {
  /** The encrypted payload bytes. */
  ciphertext: Uint8Array
} & A256GCMParams

/**
 * Symmetric AES-CTR-256 JWK used for cipher messaging operations.
 *
 * @expand
 */
export type CipherKey = A256CTRKey | A256GCMKey

/**
 * Serialized parameters required to decrypt a cipher message.
 */
export type CipherParams = A256CTRParams | A256GCMParams

/**
 * Cipher message artifact returned by cipher encryption operations.
 */
export type CipherMessage = A256CTRMessage | A256GCMMessage
