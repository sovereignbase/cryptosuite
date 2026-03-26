/*
Copyright 2026 Sovereignbase

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
export type CryptosuiteErrorCode =
  | 'BASE64URL_INVALID'
  | 'CRYPTO_UNAVAILABLE'
  | 'SUBTLE_UNAVAILABLE'
  | 'GET_RANDOM_VALUES_UNAVAILABLE'
  | 'SHA384_UNSUPPORTED'
  | 'BUFFER_SOURCE_EXPECTED'
  | 'CIPHER_KEY_INVALID'
  | 'CIPHER_MESSAGE_INVALID'
  | 'CIPHER_ARTIFACT_INVALID'
  | 'HMAC_JWK_INVALID'
  | 'VERIFY_KEY_IMPORT_FAILED'
  | 'SIGN_KEY_IMPORT_FAILED'
  | 'ALGORITHM_UNSUPPORTED'
  | 'SIGN_JWK_INVALID'
  | 'VERIFY_JWK_INVALID'
  | 'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID'
  | 'KEY_AGREEMENT_DECAPSULATE_JWK_INVALID'
  | 'KEY_AGREEMENT_KEY_INVALID'
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
