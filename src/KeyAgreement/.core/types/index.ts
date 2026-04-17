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

type KeyAgreementAlg = 'ML-KEM-1024' | 'X25519-ML-KEM-768'

type EncapsulateKeyByAlg<Alg extends KeyAgreementAlg> = JsonWebKey &
  NoSymmetric &
  NoPrivate & {
    kty: 'AKP'
    alg: Alg
    x: string
    use: 'enc'
    key_ops: readonly []
  }

type DecapsulateKeyByAlg<Alg extends KeyAgreementAlg> = JsonWebKey &
  NoSymmetric & {
    kty: 'AKP'
    alg: Alg
    d: string
    use: 'enc'
    key_ops: readonly ('deriveKey' | 'deriveBits')[]
  }

type KeyAgreementOffer = {
  /** The encapsulated shared-secret artifact emitted by a supported key agreement algorithm. */
  ciphertext: ArrayBuffer
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
 */
export type EncapsulateKey =
  | EncapsulateKeyByAlg<'ML-KEM-1024'>
  | EncapsulateKeyByAlg<'X25519-ML-KEM-768'>

/**
 * Private supported key agreement JWK used to decapsulate a shared cipher key.
 */
export type DecapsulateKey =
  | DecapsulateKeyByAlg<'ML-KEM-1024'>
  | DecapsulateKeyByAlg<'X25519-ML-KEM-768'>

/**
 * Encapsulated key agreement artifact exchanged with the counterparty.
 */
export type KeyOffer = KeyAgreementOffer

/**
 * Runtime key agreement parameters used internally by key agreement harnesses.
 */
export type KeyAgreementParams = EncapsulateParams | DecapsulateParams
