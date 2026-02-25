import { CryptosuiteError } from '../../.errors/class.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import type { HMACJWK } from '../index.js'

export async function generateHMACKey(): Promise<HMACJWK> {
  assertSubtleAvailable('generateHMACKey')
  let hmacKey: CryptoKey
  try {
    hmacKey = await crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign', 'verify']
    )
  } catch {
    throw new CryptosuiteError(
      'HMAC_SHA256_UNSUPPORTED',
      'generateHMACKey: HMAC-SHA-256 is not supported.'
    )
  }
  return (await crypto.subtle.exportKey('jwk', hmacKey)) as HMACJWK
}
