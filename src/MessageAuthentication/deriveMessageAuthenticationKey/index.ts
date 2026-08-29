import { fromString, toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { normalizeBytes } from '../../.helpers/normalizeBytes.js'
import { validateKeyByAlgCode } from '../.core/helpers/validateKeyByAlgCode/index.js'
import type { MessageAuthenticationKey } from '../.core/types/index.js'

const INFO = fromString('@sovereignbase/cryptosuite/MessageAuthenticationKey')

/**
 * Derives a symmetric message authentication key from source key material.
 *
 * @param sourceKeyMaterial - The source bytes to derive from.
 * @param salt - Optional HKDF salt. An empty salt is used when omitted.
 * @returns The derived message authentication key.
 */
export async function deriveMessageAuthenticationKey(
  sourceKeyMaterial: Uint8Array,
  salt?: Uint8Array
): Promise<MessageAuthenticationKey> {
  if (!globalThis.crypto?.subtle) {
    throw new CryptosuiteError(
      'SUBTLE_UNAVAILABLE',
      'deriveMessageAuthenticationKey: crypto.subtle is unavailable.'
    )
  }

  const sourceBytes = normalizeBytes(
    sourceKeyMaterial,
    'deriveMessageAuthenticationKey sourceKeyMaterial'
  )
  const saltBytes =
    salt === undefined
      ? new Uint8Array()
      : normalizeBytes(salt, 'deriveMessageAuthenticationKey salt')

  if (sourceBytes.byteLength === 0) {
    throw new CryptosuiteError(
      'HMAC_JWK_INVALID',
      'deriveMessageAuthenticationKey: source key material must not be empty.'
    )
  }

  let key: CryptoKey
  let derived: CryptoKey
  try {
    key = await crypto.subtle.importKey(
      'raw',
      toBufferSource(sourceBytes),
      'HKDF',
      false,
      ['deriveKey']
    )
    derived = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: toBufferSource(saltBytes),
        info: toBufferSource(INFO),
      },
      key,
      { name: 'HMAC', hash: 'SHA-256' },
      true,
      ['sign', 'verify']
    )
  } catch {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'deriveMessageAuthenticationKey: HKDF-SHA-256 to HMAC-SHA-256 is not supported by this WebCrypto runtime.'
    )
  }

  return validateKeyByAlgCode(await crypto.subtle.exportKey('jwk', derived))
}
