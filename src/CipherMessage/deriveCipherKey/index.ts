import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { getBufferSourceLength } from '../../.helpers/getBufferSourceLength.js'
import { validateKeyByAlgCode } from '../.core/helpers/validateKeyByAlgCode/index.js'
import type { CipherKey } from '../.core/types/index.js'

/**
 * Derives a symmetric cipher key from source key material.
 *
 * @param sourceKeyMaterial - The source bytes to derive from.
 * @param options - Optional derivation options.
 * @returns The derived cipher key and the salt used for derivation.
 */
export async function deriveCipherKey(
  sourceKeyMaterial: Uint8Array,
  options: {
    salt?: Uint8Array
  } = {}
): Promise<{ cipherKey: CipherKey; salt: Uint8Array }> {
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

  if (!options.salt && !globalThis.crypto?.getRandomValues) {
    throw new CryptosuiteError(
      'GET_RANDOM_VALUES_UNAVAILABLE',
      'deriveCipherKey: crypto.getRandomValues is unavailable.'
    )
  }

  const salt = options.salt ?? crypto.getRandomValues(new Uint8Array(16))
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
        salt: toBufferSource(salt),
        info: new Uint8Array(0),
      },
      key,
      { name: 'AES-CTR', length: 256 },
      true,
      ['encrypt', 'decrypt']
    )
  } catch {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'deriveCipherKey: HKDF-SHA-256 to AES-CTR-256 is not supported by this WebCrypto runtime.'
    )
  }

  const cipherKey = validateKeyByAlgCode(
    await crypto.subtle.exportKey('jwk', derived)
  )
  return {
    cipherKey,
    salt,
  }
}
