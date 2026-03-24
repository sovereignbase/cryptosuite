import { fromBase64UrlString } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../../../.errors/class.js'
import type {
  DigitalSignatureParams,
  SignKey,
  VerifyKey,
} from '../../types/index.js'

export function createParamsByAlgCode(
  key: SignKey | VerifyKey
): DigitalSignatureParams {
  if ('d' in key && typeof key.d === 'string') {
    return {
      secretKey: fromBase64UrlString(key.d),
    }
  }

  if ('x' in key && typeof key.x === 'string') {
    return {
      publicKey: fromBase64UrlString(key.x),
    }
  }

  throw new CryptosuiteError(
    'SIGN_JWK_INVALID',
    'createParamsByAlgCode: unsupported digital signature params input.'
  )
}
