import { toBufferSource } from '@z-base/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import { assertRawHmac256Bytes } from '../../.helpers/assertRawHmac256Bytes.js'
import type { HMACJWK } from '../index.js'

export async function deriveHMACKey(rawKey: Uint8Array): Promise<HMACJWK> {
  assertSubtleAvailable('deriveHMACKey')
  assertRawHmac256Bytes(rawKey, 'deriveHMACKey')
  let key: CryptoKey
  try {
    key = await crypto.subtle.importKey(
      'raw',
      toBufferSource(rawKey),
      { name: 'HMAC', hash: 'SHA-256' },
      true,
      ['sign', 'verify']
    )
  } catch {
    throw new CryptosuiteError(
      'HMAC_SHA256_UNSUPPORTED',
      'deriveHMACKey: HMAC-SHA-256 is not supported.'
    )
  }

  return (await crypto.subtle.exportKey('jwk', key)) as HMACJWK
}
