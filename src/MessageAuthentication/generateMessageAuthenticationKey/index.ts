import { CryptosuiteError } from '../../.errors/class.js'
import { validateKeyByAlgCode } from '../.core/helpers/validateKeyByAlgCode/index.js'
import type { MessageAuthenticationKey } from '../.core/types/index.js'

export async function generateMessageAuthenticationKey(): Promise<MessageAuthenticationKey> {
  if (!globalThis.crypto?.subtle) {
    throw new CryptosuiteError(
      'SUBTLE_UNAVAILABLE',
      'generateMessageAuthenticationKey: crypto.subtle is unavailable.'
    )
  }

  let messageAuthenticationKey: CryptoKey
  try {
    messageAuthenticationKey = await crypto.subtle.generateKey(
      {
        name: 'HMAC',
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify']
    )
  } catch {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'generateMessageAuthenticationKey: HMAC-SHA-256 is not supported by this WebCrypto runtime.'
    )
  }

  return validateKeyByAlgCode(
    await crypto.subtle.exportKey('jwk', messageAuthenticationKey)
  )
}
