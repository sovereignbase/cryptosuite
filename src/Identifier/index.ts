import { toBase64UrlString, toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../.errors/class.js'

export type OpaqueIdentifier = string

/**
 * Turns pads input value to a unique string presentation in a space with more options than atoms in observable universe
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
 * Generates an unique string presentation in a space with more options than atoms in observable universe
 */
export async function generateOID(): Promise<OpaqueIdentifier> {
  return toBase64UrlString(crypto.getRandomValues(new Uint8Array(48)))
}

/**
 * Validates an unique strings lenght and char encoding in a space with more options than atoms in observable universe
 */
export function validateOID(id: string): OpaqueIdentifier | false {
  if (typeof id !== 'string') return false
  if (!/^[A-Za-z0-9_-]{64}$/.test(id)) return false
  return id as OpaqueIdentifier
}
