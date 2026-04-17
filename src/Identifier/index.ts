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
import { toBase64UrlString, toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../.errors/class.js'

/**
 * Represents a fixed-length opaque identifier string.
 */
export type OpaqueIdentifier = string

/**
 * Derives a fixed-length opaque identifier from arbitrary input.
 *
 * The output is intentionally non-semantic:
 * - fixed width
 * - base64url encoded
 * - no embedded resource metadata
 *
 * @param source - The source bytes to map deterministically into an identifier.
 * @returns A derived opaque identifier in normalized presentation.
 */
export async function deriveOID(source: Uint8Array): Promise<OpaqueIdentifier> {
  if (!globalThis.crypto?.subtle) {
    throw new CryptosuiteError(
      'SUBTLE_UNAVAILABLE',
      'deriveOID: crypto.subtle is unavailable.'
    )
  }

  let hash: ArrayBuffer
  try {
    hash = await globalThis.crypto.subtle.digest(
      'SHA-384',
      toBufferSource(source)
    )
  } catch {
    throw new CryptosuiteError(
      'SHA384_UNSUPPORTED',
      'deriveOID: SHA-384 is not supported.'
    )
  }
  return toBase64UrlString(hash)
}

/**
 * Generates a fixed-length opaque identifier with the same presentation as
 * derived identifiers.
 *
 * @returns A randomly generated opaque identifier.
 */
export async function generateOID(): Promise<OpaqueIdentifier> {
  if (!globalThis.crypto?.getRandomValues) {
    throw new CryptosuiteError(
      'GET_RANDOM_VALUES_UNAVAILABLE',
      'generateOID: crypto.getRandomValues is unavailable.'
    )
  }

  return toBase64UrlString(globalThis.crypto.getRandomValues(new Uint8Array(48)))
}

/**
 * Validates the opaque identifier presentation only.
 *
 * Validation is intentionally structural:
 * length and encoding only, never semantics.
 *
 * @param id - The candidate identifier string to validate.
 * @returns The normalized opaque identifier when valid; otherwise `false`.
 */
export function validateOID(id: string): OpaqueIdentifier | false {
  if (typeof id !== 'string') return false
  if (!/^[A-Za-z0-9_-]{64}$/.test(id)) return false
  return id as OpaqueIdentifier
}
