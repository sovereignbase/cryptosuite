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

type HS256Key = JsonWebKey &
  NoAsymmetric & {
    kty: 'oct'
    k: string
    alg: 'HS256'
    use: 'sig'
    key_ops: readonly ('sign' | 'verify')[]
  }

type HMACParams = Record<never, never>

/**
 * Symmetric HMAC-SHA-256 JWK used for message authentication operations.
 */
export type MessageAuthenticationKey = HS256Key

/**
 * Algorithm parameters for message authentication operations.
 *
 * HMAC does not currently require serialized per-message parameters.
 */
export type MessageAuthenticationParams = HMACParams
