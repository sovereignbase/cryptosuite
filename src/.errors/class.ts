/**
 * Semantic error codes exposed by the cryptosuite public API.
 */
export type CryptosuiteErrorCode =
  | 'BASE64URL_INVALID'
  | 'SUBTLE_UNAVAILABLE'
  | 'GET_RANDOM_VALUES_UNAVAILABLE'
  | 'BUFFER_SOURCE_EXPECTED'
  | 'CIPHER_KEY_INVALID'
  | 'CIPHER_MESSAGE_INVALID'
  | 'CIPHER_ARTIFACT_INVALID'
  | 'HMAC_JWK_INVALID'
  | 'ALGORITHM_UNSUPPORTED'
  | 'SIGN_JWK_INVALID'
  | 'VERIFY_JWK_INVALID'
  | 'KEY_AGREEMENT_KEY_INVALID'
  | 'KEY_AGREEMENT_ARTIFACT_INVALID'
  | 'DECAPSULATION_FAILED'
  | 'ENCAPSULATION_FAILED'
  | 'EXPORT_FAILED'

/**
 * Typed error used by the cryptosuite public API.
 */
export class CryptosuiteError extends Error {
  /**
   * Stable semantic code describing the failure condition.
   */
  readonly code: CryptosuiteErrorCode

  /**
   * Creates a cryptosuite error with a package-scoped message prefix.
   *
   * @param code Stable semantic code for the failure condition.
   * @param message Optional human-readable detail. Defaults to `code`.
   */
  constructor(code: CryptosuiteErrorCode, message?: string) {
    const detail = message ?? code
    super(`{@sovereignbase/cryptosuite} ${detail}`)
    this.code = code
    this.name = 'CryptosuiteError'
  }
}
