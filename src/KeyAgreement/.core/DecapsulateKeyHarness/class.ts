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
import { CryptosuiteError } from '../../../.errors/class.js'
import { validateKeyByAlgCode } from '../helpers/validateKeyByAlgCode/index.js'
import { createImportKeyAlgorithmByAlgCode } from '../helpers/createImportKeyAlgorithmByAlgCode/index.js'
import { createParamsByAlgCode } from '../helpers/createParamsByAlgCode/index.js'
import { getParamsByAlgCode } from '../helpers/getParamsByAlgCode/index.js'
import { validateKeyByAlgCode as validateCipherKeyByAlgCode } from '../../../CipherMessage/.core/helpers/validateKeyByAlgCode/index.js'
import type { CipherKey } from '../../../CipherMessage/.core/types/index.js'
import type {
  DecapsulateKey,
  DecapsulateKey as DecapsulateAlgKey,
  KeyAgreementParams,
  KeyOffer,
} from '../types/index.js'

export class DecapsulateKeyHarness {
  private readonly algCode: DecapsulateAlgKey['alg']
  private readonly params: KeyAgreementParams
  private readonly kem: ReturnType<typeof createImportKeyAlgorithmByAlgCode>

  constructor(decapsulateKey: DecapsulateKey) {
    if (!globalThis.crypto?.subtle) {
      throw new CryptosuiteError(
        'SUBTLE_UNAVAILABLE',
        'DecapsulateKeyHarness: crypto.subtle is unavailable.'
      )
    }

    const validated = validateKeyByAlgCode(decapsulateKey)
    if (!('d' in validated)) {
      throw new CryptosuiteError(
        'KEY_AGREEMENT_KEY_INVALID',
        'DecapsulateKeyHarness: expected a private decapsulation key.'
      )
    }

    this.algCode = validated.alg
    this.params = createParamsByAlgCode(validated)
    this.kem = createImportKeyAlgorithmByAlgCode(this.algCode)
  }

  private async exportCipherKey(sharedSecret: Uint8Array): Promise<CipherKey> {
    let cipherKey: CryptoKey
    try {
      cipherKey = await crypto.subtle.importKey(
        'raw',
        toBufferSource(sharedSecret),
        { name: 'AES-CTR', length: 256 },
        true,
        ['encrypt', 'decrypt']
      )
    } catch {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'DecapsulateKeyHarness: AES-CTR-256 is not supported by this WebCrypto runtime.'
      )
    }

    try {
      return validateCipherKeyByAlgCode(
        await crypto.subtle.exportKey('jwk', cipherKey)
      )
    } catch (error) {
      if (error instanceof CryptosuiteError) throw error
      throw new CryptosuiteError(
        'EXPORT_FAILED',
        'DecapsulateKeyHarness: failed to export the shared cipher key.'
      )
    }
  }

  async decapsulate(keyOffer: KeyOffer): Promise<{ cipherKey: CipherKey }> {
    if (
      !keyOffer ||
      typeof keyOffer !== 'object' ||
      !(keyOffer.ciphertext instanceof ArrayBuffer)
    ) {
      throw new CryptosuiteError(
        'KEY_AGREEMENT_ARTIFACT_INVALID',
        'DecapsulateKeyHarness.decapsulate: expected a key offer with ciphertext.'
      )
    }

    const params = getParamsByAlgCode(this.algCode, this.params)
    if (!('secretKey' in params)) {
      throw new CryptosuiteError(
        'KEY_AGREEMENT_KEY_INVALID',
        'DecapsulateKeyHarness.decapsulate: expected decapsulation private key params.'
      )
    }

    if (keyOffer.ciphertext.byteLength !== this.kem.lengths.cipherText) {
      throw new CryptosuiteError(
        'KEY_AGREEMENT_ARTIFACT_INVALID',
        'DecapsulateKeyHarness.decapsulate: key offer ciphertext has invalid length.'
      )
    }

    try {
      const sharedSecret = this.kem.decapsulate(
        new Uint8Array(keyOffer.ciphertext),
        params.secretKey
      )
      return {
        cipherKey: await this.exportCipherKey(sharedSecret),
      }
    } catch {
      throw new CryptosuiteError(
        'DECAPSULATION_FAILED',
        'DecapsulateKeyHarness.decapsulate: failed to decapsulate the shared cipher key.'
      )
    }
  }
}
