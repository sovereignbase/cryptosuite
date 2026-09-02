import { Bytes } from '@sovereignbase/bytecodec'
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
      secretKey: Bytes.base64url.decode(key.d),
    }
  }

  if ('x' in key && typeof key.x === 'string') {
    return {
      publicKey: Bytes.base64url.decode(key.x),
    }
  }

  throw new CryptosuiteError(
    'SIGN_JWK_INVALID',
    'createParamsByAlgCode: unsupported digital signature params input.'
  )
}
