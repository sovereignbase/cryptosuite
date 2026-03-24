/*
Copyright 2026 z-base

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

type A256CTRKey = JsonWebKey &
  NoAsymmetric & {
    kty: 'oct'
    k: string
    alg: 'A256CTR'
    use: 'enc'
    key_ops: readonly ('encrypt' | 'decrypt')[]
  }

export type A256CTRParams = {
  iv: Uint8Array
}

type A256CTRMessage = {
  ciphertext: ArrayBuffer
} & A256CTRParams

export type CipherKey = A256CTRKey

export type CipherParams = A256CTRParams

export type CipherMessage = A256CTRMessage
