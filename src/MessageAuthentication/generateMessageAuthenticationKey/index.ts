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
import { CryptosuiteError } from '../../.errors/class.js'
import { validateKeyByAlgCode } from '../.core/helpers/validateKeyByAlgCode/index.js'
import type { MessageAuthenticationKey } from '../.core/types/index.js'

/**
 * Generates a new symmetric message authentication key.
 *
 * @returns A newly generated message authentication key.
 */
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
