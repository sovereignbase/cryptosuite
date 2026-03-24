import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../../.errors/class.js'
import { validateKeyByAlgCode } from '../helpers/validateKeyByAlgCode/index.js'
import { createImportKeyAlgorithmByAlgCode } from '../helpers/createImportKeyAlgorithmByAlgCode/index.js'
import { createParamsByAlgCode } from '../helpers/createParamsByAlgCode/index.js'
import { getParamsByAlgCode } from '../helpers/getParamsByAlgCode/index.js'
import { validateKeyByAlgCode as validateCipherKeyByAlgCode } from '../../../CipherMessage/.core/helpers/validateKeyByAlgCode/index.js'
import type { CipherKey } from '../../../CipherMessage/.core/types/index.js'
import type {
  EncapsulateKey,
  EncapsulateKey as EncapsulateAlgKey,
  KeyAgreementParams,
  KeyOffer,
} from '../types/index.js'

export class EncapsulateKeyHarness {
  private readonly algCode: EncapsulateAlgKey['alg']
  private readonly params: KeyAgreementParams
  private readonly kem: ReturnType<typeof createImportKeyAlgorithmByAlgCode>

  constructor(encapsulateKey: EncapsulateKey) {
    if (!globalThis.crypto?.subtle) {
      throw new CryptosuiteError(
        'SUBTLE_UNAVAILABLE',
        'EncapsulateKeyHarness: crypto.subtle is unavailable.'
      )
    }

    const validated = validateKeyByAlgCode(encapsulateKey)
    if (!('x' in validated)) {
      throw new CryptosuiteError(
        'KEY_AGREEMENT_KEY_INVALID',
        'EncapsulateKeyHarness: expected a public encapsulation key.'
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
        'EncapsulateKeyHarness: AES-CTR-256 is not supported by this WebCrypto runtime.'
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
        'EncapsulateKeyHarness: failed to export the shared cipher key.'
      )
    }
  }

  async encapsulate(): Promise<{ keyOffer: KeyOffer; cipherKey: CipherKey }> {
    const params = getParamsByAlgCode(this.algCode, this.params)
    if (!('publicKey' in params)) {
      throw new CryptosuiteError(
        'KEY_AGREEMENT_KEY_INVALID',
        'EncapsulateKeyHarness.encapsulate: expected encapsulation public key params.'
      )
    }

    try {
      const { cipherText, sharedSecret } = this.kem.encapsulate(
        params.publicKey
      )
      const ciphertext = cipherText.slice()
      return {
        keyOffer: { ciphertext: ciphertext.buffer as ArrayBuffer },
        cipherKey: await this.exportCipherKey(sharedSecret),
      }
    } catch {
      throw new CryptosuiteError(
        'ENCAPSULATION_FAILED',
        'EncapsulateKeyHarness.encapsulate: failed to encapsulate a shared cipher key.'
      )
    }
  }
}
