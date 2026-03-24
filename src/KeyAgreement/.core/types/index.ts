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

type MLKEM1024EncapsulateKey = JsonWebKey &
  NoSymmetric &
  NoPrivate & {
    kty: 'AKP'
    alg: 'ML-KEM-1024'
    x: string
    use: 'enc'
    key_ops: readonly []
  }

type MLKEM1024DecapsulateKey = JsonWebKey &
  NoSymmetric & {
    kty: 'AKP'
    alg: 'ML-KEM-1024'
    d: string
    use: 'enc'
    key_ops: readonly ('deriveKey' | 'deriveBits')[]
  }

type MLKEM1024KeyOffer = {
  ciphertext: ArrayBuffer
}

type MLKEM1024EncapsulateParams = {
  publicKey: Uint8Array
}

type MLKEM1024DecapsulateParams = {
  secretKey: Uint8Array
}

export type EncapsulateKey = MLKEM1024EncapsulateKey

export type DecapsulateKey = MLKEM1024DecapsulateKey

export type KeyOffer = MLKEM1024KeyOffer

export type KeyAgreementParams =
  | MLKEM1024EncapsulateParams
  | MLKEM1024DecapsulateParams
