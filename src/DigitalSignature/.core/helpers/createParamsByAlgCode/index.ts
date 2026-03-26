/*
Copyright 2026 Sovereignbase

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
