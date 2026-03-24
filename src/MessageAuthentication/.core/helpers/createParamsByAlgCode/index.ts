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
import { CryptosuiteError } from '../../../../.errors/class.js'
import type {
  MessageAuthenticationKey,
  MessageAuthenticationParams,
} from '../../types/index.js'

export function createParamsByAlgCode(
  algCode: MessageAuthenticationKey['alg']
): MessageAuthenticationParams {
  switch (algCode) {
    case 'HS256':
      return {}
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `createParamsByAlgCode: unsupported message authentication JWK alg "${algCode}"; expected HS256.`
  )
}
