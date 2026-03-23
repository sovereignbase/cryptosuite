import { CryptosuiteError } from '../../.errors/class.js'
import type { CipherKey } from '../.core/types/index.js'
import { validateKeyByAlgCode } from '../.core/helpers/validateKeyByAlgCode/index.js'

export async function generateCipherKey(): Promise<CipherKey> {
  if (!globalThis.crypto?.subtle) {
    throw new CryptosuiteError(
      'SUBTLE_UNAVAILABLE',
      'generateCipherKey: crypto.subtle is unavailable.'
    )
  }

  let cipherKey: CryptoKey
  try {
    cipherKey = await crypto.subtle.generateKey(
      { name: 'AES-CTR', length: 256 },
      true,
      ['encrypt', 'decrypt']
    )
  } catch {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'generateCipherKey: AES-CTR-256 is not supported by this WebCrypto runtime.'
    )
  }

  return validateKeyByAlgCode(await crypto.subtle.exportKey('jwk', cipherKey))
}
