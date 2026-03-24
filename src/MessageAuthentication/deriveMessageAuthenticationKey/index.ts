/*
Copyright 2026 z-base

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { getBufferSourceLength } from '../../.helpers/getBufferSourceLength.js'
import { validateKeyByAlgCode } from '../.core/helpers/validateKeyByAlgCode/index.js'
import type { MessageAuthenticationKey } from '../.core/types/index.js'

/**
 * Derives a symmetric message authentication key from source key material.
 *
 * @param sourceKeyMaterial - The source bytes to derive from.
 * @param options - Optional derivation options.
 * @returns The derived message authentication key and the salt used.
 */
export async function deriveMessageAuthenticationKey(
  sourceKeyMaterial: Uint8Array,
  options: {
    salt?: Uint8Array
  } = {}
): Promise<{
  messageAuthenticationKey: MessageAuthenticationKey
  salt: Uint8Array
}> {
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

  if (!options.salt && !globalThis.crypto?.getRandomValues) {
    throw new CryptosuiteError(
      'GET_RANDOM_VALUES_UNAVAILABLE',
      'deriveMessageAuthenticationKey: crypto.getRandomValues is unavailable.'
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

  const messageAuthenticationKey = validateKeyByAlgCode(
    await crypto.subtle.exportKey('jwk', derived)
  )
  return {
    messageAuthenticationKey,
    salt,
  }
}
