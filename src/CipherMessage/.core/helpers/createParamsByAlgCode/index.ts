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
import type { CipherKey, CipherParams } from '../../types/index.js'

export function createParamsByAlgCode(algCode: CipherKey['alg']): CipherParams {
  switch (algCode) {
    case 'A256CTR':
      if (!globalThis.crypto?.getRandomValues) {
        throw new CryptosuiteError(
          'GET_RANDOM_VALUES_UNAVAILABLE',
          'createParamsByAlgCode: crypto.getRandomValues is unavailable.'
        )
      }

      return {
        iv: crypto.getRandomValues(new Uint8Array(12)),
      }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `createParamsByAlgCode: unsupported cipher JWK alg "${algCode}".`
  )
}
