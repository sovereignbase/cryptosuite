import { toBase64UrlString, toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../.errors/class.js'
import { assertGetRandomValuesAvailable } from '../.helpers/assertGetRandomValuesAvailable.js'
import { assertSubtleAvailable } from '../.helpers/assertSubtleAvailable.js'

export type ObliviousIdentifier = string

/**
 * Turns pads input value to a unique string presentation in a space with more options than atoms in observable universe
 */
export async function deriveOID(
  source: Uint8Array
): Promise<ObliviousIdentifier> {
  assertSubtleAvailable('deriveOID')
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
export async function generateOID(): Promise<ObliviousIdentifier> {
  assertGetRandomValuesAvailable('generateOID')
  return toBase64UrlString(crypto.getRandomValues(new Uint8Array(48)))
}

/**
 * Validates an unique strings lenght and char encoding in a space with more options than atoms in observable universe
 */
export function validateOID(id: string): ObliviousIdentifier | false {
  if (typeof id !== 'string') return false
  if (!/^[A-Za-z0-9_-]{64}$/.test(id)) return false
  return id as ObliviousIdentifier
}
