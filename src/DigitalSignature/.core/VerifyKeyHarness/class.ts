import { CryptosuiteError } from '../../../.errors/class.js'
import { createImportKeyAlgorithmByAlgCode } from '../helpers/createImportKeyAlgorithmByAlgCode/index.js'
import { createParamsByAlgCode } from '../helpers/createParamsByAlgCode/index.js'
import { getParamsByAlgCode } from '../helpers/getParamsByAlgCode/index.js'
import { validateKeyByAlgCode } from '../helpers/validateKeyByAlgCode/index.js'
import type {
  DigitalSignatureParams,
  VerifyKey,
  VerifyKey as VerifyAlgKey,
} from '../types/index.js'

export class VerifyKeyHarness {
  private readonly algCode: VerifyAlgKey['alg']
  private readonly params: DigitalSignatureParams
  private readonly verifier: ReturnType<
    typeof createImportKeyAlgorithmByAlgCode
  >

  constructor(verifyKey: VerifyKey) {
    const validated = validateKeyByAlgCode(verifyKey)
    if (!('x' in validated)) {
      throw new CryptosuiteError(
        'VERIFY_JWK_INVALID',
        'VerifyKeyHarness: expected a public verify key.'
      )
    }

    this.algCode = validated.alg
    this.params = createParamsByAlgCode(validated)
    this.verifier = createImportKeyAlgorithmByAlgCode(this.algCode)
  }

  async verify(bytes: Uint8Array, signature: Uint8Array): Promise<boolean> {
    const params = getParamsByAlgCode(this.algCode, this.params)
    if (!('publicKey' in params)) {
      throw new CryptosuiteError(
        'VERIFY_JWK_INVALID',
        'VerifyKeyHarness.verify: expected verify key params.'
      )
    }

    try {
      return this.verifier.verify(signature, bytes, params.publicKey)
    } catch {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'VerifyKeyHarness.verify: failed to verify with ML-DSA-87.'
      )
    }
  }
}
