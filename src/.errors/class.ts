export type CryptosuiteErrorCode =
  | 'BASE64URL_INVALID'
  | 'CRYPTO_UNAVAILABLE'
  | 'SUBTLE_UNAVAILABLE'
  | 'GET_RANDOM_VALUES_UNAVAILABLE'
  | 'SHA384_UNSUPPORTED'
  | 'BUFFER_SOURCE_EXPECTED'
  | 'CIPHER_JWK_INVALID'
  | 'CIPHER_ARTIFACT_INVALID'
  | 'HMAC_JWK_INVALID'
  | 'VERIFY_KEY_IMPORT_FAILED'
  | 'SIGN_KEY_IMPORT_FAILED'
  | 'ALGORITHM_UNSUPPORTED'
  | 'SIGN_JWK_INVALID'
  | 'VERIFY_JWK_INVALID'
  | 'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID'
  | 'KEY_AGREEMENT_DECAPSULATE_JWK_INVALID'
  | 'KEY_AGREEMENT_ARTIFACT_INVALID'
  | 'DECAPSULATION_FAILED'
  | 'ENCAPSULATION_FAILED'
  | 'EXPORT_FAILED'

export class CryptosuiteError extends Error {
  readonly code: CryptosuiteErrorCode

  constructor(code: CryptosuiteErrorCode, message?: string) {
    const detail = message ?? code
    super(`{@sovereignbase/cryptosuite} ${detail}`)
    this.code = code
    this.name = 'CryptosuiteError'
  }
}
