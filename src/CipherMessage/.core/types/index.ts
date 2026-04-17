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

type CipherAlg = 'A256CTR' | 'A256GCM'

type CipherKeyByAlg<Alg extends CipherAlg> = JsonWebKey &
  NoAsymmetric & {
    kty: 'oct'
    k: string
    alg: Alg
    use: 'enc'
    key_ops: readonly ('encrypt' | 'decrypt')[]
  }

/**
 * Algorithm parameters serialized alongside an AES-CTR cipher message.
 */
export type A256CTRParams = {
  /** The 96-bit initialization vector used for encryption. */
  iv: Uint8Array
}

/**
 * Algorithm parameters serialized alongside an AES-GCM cipher message.
 */
export type A256GCMParams = {
  /** The 96-bit initialization vector used for encryption. */
  iv: Uint8Array
}

type A256CTRMessage = {
  /** The encrypted payload bytes. */
  ciphertext: ArrayBuffer
} & A256CTRParams

type A256GCMMessage = {
  /** The encrypted payload bytes. */
  ciphertext: ArrayBuffer
} & A256GCMParams

/**
 * Symmetric AES-CTR-256 JWK used for cipher messaging operations.
 */
export type CipherKey = CipherKeyByAlg<'A256CTR'> | CipherKeyByAlg<'A256GCM'>

/**
 * Serialized parameters required to decrypt a cipher message.
 */
export type CipherParams = A256CTRParams | A256GCMParams

/**
 * Cipher message artifact returned by cipher encryption operations.
 */
export type CipherMessage = A256CTRMessage | A256GCMMessage
