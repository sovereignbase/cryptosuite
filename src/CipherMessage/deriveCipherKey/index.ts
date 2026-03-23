import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import { assertRawAesGcm256Bytes } from '../../.helpers/assertRawAesGcm256Bytes.js'
import type { CipherJWK } from '../index.js'

export async function deriveCipherKey(rawKey: Uint8Array): Promise<CipherJWK> {
  assertSubtleAvailable('deriveCipherKey')
  assertRawAesGcm256Bytes(rawKey, 'deriveCipherKey')
  let key: CryptoKey
  try {
    key = await crypto.subtle.importKey(
      'raw',
      toBufferSource(rawKey),
      { name: 'AES-GCM' },
      true,
      ['encrypt', 'decrypt']
    )
  } catch {
    throw new CryptosuiteError(
      'AES_GCM_UNSUPPORTED',
      'deriveCipherKey: AES-GCM is not supported.'
    )
  }
  return (await crypto.subtle.exportKey('jwk', key)) as CipherJWK
}
