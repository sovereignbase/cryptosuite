import { toBase64UrlString, toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../.errors/class.js'

export type OpaqueIdentifier = string

/**
 * Derives a fixed-length opaque identifier from arbitrary input.
 *
 * The output is intentionally non-semantic:
 * - fixed width
 * - base64url encoded
 * - no embedded resource metadata
 */
export async function deriveOID(source: Uint8Array): Promise<OpaqueIdentifier> {
  let hash: ArrayBuffer
  try {
    hash = await crypto.subtle.digest('SHA-384', toBufferSource(source))
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
 */
export async function generateOID(): Promise<OpaqueIdentifier> {
  return toBase64UrlString(crypto.getRandomValues(new Uint8Array(48)))
}

/**
 * Validates the opaque identifier presentation only.
 *
 * Validation is intentionally structural:
 * length and encoding only, never semantics.
 */
export function validateOID(id: string): OpaqueIdentifier | false {
  if (typeof id !== 'string') return false
  if (!/^[A-Za-z0-9_-]{64}$/.test(id)) return false
  return id as OpaqueIdentifier
}
