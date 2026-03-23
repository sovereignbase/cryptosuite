import { CryptosuiteError } from '../../.errors/class.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import { normalizeHMACJWK } from '../normalizeHMACJWK/index.js'
import type { HMACJWK } from '../types/index.js'

export async function generateHMACKey(
  algorithm: { hash?: string; length?: number; alg?: string } = {}
): Promise<HMACJWK> {
  assertSubtleAvailable('generateHMACKey')
  let hmacKey: CryptoKey
  try {
    hmacKey = await crypto.subtle.generateKey(
      {
        name: 'HMAC',
        hash: algorithm.hash ?? 'SHA-256',
        ...(algorithm.length === undefined ? {} : { length: algorithm.length }),
      },
      true,
      ['sign', 'verify']
    )
  } catch {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'generateHMACKey: selected HMAC algorithm is not supported by this WebCrypto runtime.'
    )
  }
  return normalizeHMACJWK({
    ...(await crypto.subtle.exportKey('jwk', hmacKey)),
    ...(algorithm.alg === undefined ? {} : { alg: algorithm.alg }),
    ...(algorithm.hash === undefined ? {} : { hash: algorithm.hash }),
  })
}
