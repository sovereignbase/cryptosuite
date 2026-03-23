import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import { normalizeHMACJWK } from '../normalizeHMACJWK/index.js'
import type { HMACJWK } from '../types/index.js'

export async function deriveHMACKey(
  rawKey: Uint8Array,
  algorithm: { hash?: string; alg?: string } = {}
): Promise<HMACJWK> {
  assertSubtleAvailable('deriveHMACKey')
  let key: CryptoKey
  try {
    key = await crypto.subtle.importKey(
      'raw',
      toBufferSource(rawKey),
      { name: 'HMAC', hash: algorithm.hash ?? 'SHA-256' },
      true,
      ['sign', 'verify']
    )
  } catch {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'deriveHMACKey: selected HMAC algorithm is not supported by this WebCrypto runtime.'
    )
  }

  return normalizeHMACJWK({
    ...(await crypto.subtle.exportKey('jwk', key)),
    ...(algorithm.alg === undefined ? {} : { alg: algorithm.alg }),
    ...(algorithm.hash === undefined ? {} : { hash: algorithm.hash }),
  })
}
