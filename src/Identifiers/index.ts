import { toBase64UrlString, toBufferSource } from '@z-base/bytecodec'
import { CryptosuiteError } from '../.errors/class.js'
import { assertGetRandomValuesAvailable } from '../.helpers/assertGetRandomValuesAvailable.js'
import { assertSubtleAvailable } from '../.helpers/assertSubtleAvailable.js'

export type OpaqueIdentifier = Base64URLString

export async function deriveOID(rawId: Uint8Array): Promise<OpaqueIdentifier> {
  assertSubtleAvailable('deriveOID')
  let hash: ArrayBuffer
  try {
    hash = await crypto.subtle.digest('SHA-256', toBufferSource(rawId))
  } catch {
    throw new CryptosuiteError(
      'SHA256_UNSUPPORTED',
      'deriveOID: SHA-256 is not supported.'
    )
  }
  return toBase64UrlString(hash)
}

export async function generateOID(): Promise<OpaqueIdentifier> {
  assertGetRandomValuesAvailable('generateOID')
  return toBase64UrlString(crypto.getRandomValues(new Uint8Array(32)))
}

export function validateOID(id: string): OpaqueIdentifier | false {
  if (typeof id !== 'string') return false
  if (!/^[A-Za-z0-9_-]{43}$/.test(id)) return false
  return id as OpaqueIdentifier
}
