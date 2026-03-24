import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { getBufferSourceLength } from '../../.helpers/getBufferSourceLength.js'
import { validateKeyByAlgCode } from '../.core/helpers/validateKeyByAlgCode/index.js'
import type { MessageAuthenticationKey } from '../.core/types/index.js'

/**
 * Derives a symmetric message authentication key from source key material.
 *
 * @param sourceKeyMaterial - The source bytes to derive from.
 * @returns The derived message authentication key.
 */
export async function deriveMessageAuthenticationKey(
  sourceKeyMaterial: Uint8Array
): Promise<MessageAuthenticationKey> {
  if (!globalThis.crypto?.subtle) {
    throw new CryptosuiteError(
      'SUBTLE_UNAVAILABLE',
      'deriveMessageAuthenticationKey: crypto.subtle is unavailable.'
    )
  }

  if (
    getBufferSourceLength(
      sourceKeyMaterial,
      'deriveMessageAuthenticationKey'
    ) === 0
  ) {
    throw new CryptosuiteError(
      'HMAC_JWK_INVALID',
      'deriveMessageAuthenticationKey: source key material must not be empty.'
    )
  }

  let key: CryptoKey
  try {
    key = await crypto.subtle.importKey(
      'raw',
      toBufferSource(sourceKeyMaterial),
      { name: 'HMAC', hash: 'SHA-256' },
      true,
      ['sign', 'verify']
    )
  } catch {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'deriveMessageAuthenticationKey: HMAC-SHA-256 is not supported by this WebCrypto runtime.'
    )
  }

  return validateKeyByAlgCode(await crypto.subtle.exportKey('jwk', key))
}
