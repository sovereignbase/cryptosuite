import { Bytes } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../../../.errors/class.js'
import type {
  DecapsulateKey,
  EncapsulateKey,
  KeyAgreementParams,
} from '../../types/index.js'

export function createParamsByAlgCode(
  key: EncapsulateKey | DecapsulateKey
): KeyAgreementParams {
  if ('x' in key && typeof key.x === 'string') {
    return {
      publicKey: Bytes.base64url.decode(key.x),
    }
  }

  if ('d' in key && typeof key.d === 'string') {
    return {
      secretKey: Bytes.base64url.decode(key.d),
    }
  }

  throw new CryptosuiteError(
    'KEY_AGREEMENT_KEY_INVALID',
    'createParamsByAlgCode: unsupported key agreement params input.'
  )
}
