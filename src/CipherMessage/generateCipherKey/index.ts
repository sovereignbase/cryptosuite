import { CryptosuiteError } from '../../.errors/class.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import type { CipherJWK } from '../index.js'

export async function generateCipherKey(): Promise<CipherJWK> {
  assertSubtleAvailable('generateCipherKey')
  let aesKey: CryptoKey
  try {
    aesKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    )
  } catch {
    throw new CryptosuiteError(
      'AES_GCM_UNSUPPORTED',
      'generateCipherKey: AES-GCM is not supported.'
    )
  }
  return (await crypto.subtle.exportKey('jwk', aesKey)) as CipherJWK
}
