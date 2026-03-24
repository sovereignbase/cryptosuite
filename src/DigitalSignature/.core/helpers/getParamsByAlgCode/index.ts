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
import { CryptosuiteError } from '../../../../.errors/class.js'
import type {
  DigitalSignatureParams,
  SignKey,
  VerifyKey,
} from '../../types/index.js'

export function getParamsByAlgCode(
  algCode: SignKey['alg'] | VerifyKey['alg'],
  params: DigitalSignatureParams
): DigitalSignatureParams {
  switch (algCode) {
    case 'ML-DSA-87':
      return params
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `getParamsByAlgCode: unsupported digital signature alg "${algCode}".`
  )
}
