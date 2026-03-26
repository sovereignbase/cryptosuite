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
type NoPrivate = {
  d?: never
  p?: never
  q?: never
  dp?: never
  dq?: never
  qi?: never
  k?: never
}

type MLDSA87VerifyKey = JsonWebKey &
  NoPrivate & {
    kty: 'AKP'
    alg: 'ML-DSA-87'
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

type MLDSA87SignKey = JsonWebKey &
  NoSymmetric &
  HasPrivate & {
    kty: 'AKP'
    alg: 'ML-DSA-87'
    use: 'sig'
    key_ops: readonly 'sign'[]
  }

type MLDSA87VerifyParams = {
  /** The raw ML-DSA-87 public key bytes. */
  publicKey: Uint8Array
}

type MLDSA87SignParams = {
  /** The raw ML-DSA-87 secret key bytes. */
  secretKey: Uint8Array
}

/**
 * Public ML-DSA-87 JWK used to verify signatures.
 */
export type VerifyKey = MLDSA87VerifyKey

/**
 * Private ML-DSA-87 JWK used to produce signatures.
 */
export type SignKey = MLDSA87SignKey

/**
 * Runtime ML-DSA-87 key material used internally by signing and verification harnesses.
 */
export type DigitalSignatureParams = MLDSA87VerifyParams | MLDSA87SignParams
