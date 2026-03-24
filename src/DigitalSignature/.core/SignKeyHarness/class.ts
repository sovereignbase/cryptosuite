import { CryptosuiteError } from '../../../.errors/class.js'
import { createImportKeyAlgorithmByAlgCode } from '../helpers/createImportKeyAlgorithmByAlgCode/index.js'
import { createParamsByAlgCode } from '../helpers/createParamsByAlgCode/index.js'
import { getParamsByAlgCode } from '../helpers/getParamsByAlgCode/index.js'
import { validateKeyByAlgCode } from '../helpers/validateKeyByAlgCode/index.js'
import type {
  DigitalSignatureParams,
  SignKey,
  SignKey as SignAlgKey,
} from '../types/index.js'

export class SignKeyHarness {
  private readonly algCode: SignAlgKey['alg']
  private readonly params: DigitalSignatureParams
  private readonly signer: ReturnType<typeof createImportKeyAlgorithmByAlgCode>

  constructor(signKey: SignKey) {
    const validated = validateKeyByAlgCode(signKey)
    if (!('d' in validated)) {
      throw new CryptosuiteError(
        'SIGN_JWK_INVALID',
        'SignKeyHarness: expected a private sign key.'
      )
    }

    this.algCode = validated.alg
    this.params = createParamsByAlgCode(validated)
    this.signer = createImportKeyAlgorithmByAlgCode(this.algCode)
  }

  async sign(bytes: Uint8Array): Promise<Uint8Array> {
    const params = getParamsByAlgCode(this.algCode, this.params)
    if (!('secretKey' in params)) {
      throw new CryptosuiteError(
        'SIGN_JWK_INVALID',
        'SignKeyHarness.sign: expected sign key params.'
      )
    }

    try {
      return this.signer.sign(bytes, params.secretKey)
    } catch {
      throw new CryptosuiteError(
        'ALGORITHM_UNSUPPORTED',
        'SignKeyHarness.sign: failed to sign with ML-DSA-87.'
      )
    }
  }
}
