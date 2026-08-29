import { fromString, toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { getBufferSourceLength } from '../../.helpers/getBufferSourceLength.js'
import { validateKeyByAlgCode } from '../.core/helpers/validateKeyByAlgCode/index.js'
import type { CipherKey } from '../.core/types/index.js'

const INFO = fromString('@sovereignbase/cryptosuite/CipherKey')

/**
 * Derives a symmetric cipher key from source key material.
 *
 * @param sourceKeyMaterial - The source bytes to derive from.
 * @param salt - Optional HKDF salt. An empty salt is used when omitted.
 * @returns The derived cipher key.
 */
export async function deriveCipherKey(
  sourceKeyMaterial: Uint8Array,
  salt?: Uint8Array
): Promise<CipherKey> {
  if (!globalThis.crypto?.subtle) {
    throw new CryptosuiteError(
      'SUBTLE_UNAVAILABLE',
      'deriveCipherKey: crypto.subtle is unavailable.'
    )
  }

  if (getBufferSourceLength(sourceKeyMaterial, 'deriveCipherKey') === 0) {
    throw new CryptosuiteError(
      'CIPHER_KEY_INVALID',
      'deriveCipherKey: source key material must not be empty.'
    )
  }

  let key: CryptoKey
  let derived: CryptoKey
  try {
    key = await crypto.subtle.importKey(
      'raw',
      toBufferSource(sourceKeyMaterial),
      'HKDF',
      false,
      ['deriveKey']
    )
    derived = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: toBufferSource(salt ?? new Uint8Array()),
        info: toBufferSource(INFO),
      },
      key,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    )
  } catch {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'deriveCipherKey: HKDF-SHA-256 to AES-GCM-256 is not supported by this WebCrypto runtime.'
    )
  }

  return validateKeyByAlgCode(await crypto.subtle.exportKey('jwk', derived))
}
