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
  CipherKey,
  CipherParams,
  A256CTRParams,
} from '../../types/index.js'

export function getParamsByAlgCode(
  algCode: CipherKey['alg'],
  params: CipherParams
): AesCtrParams {
  switch (algCode) {
    case 'A256CTR': {
      const { iv } = params as A256CTRParams

      if (!(iv instanceof Uint8Array)) {
        throw new CryptosuiteError(
          'CIPHER_MESSAGE_INVALID',
          'getParamsByAlgCode: expected a Uint8Array iv for AES-CTR.'
        )
      }

      if (iv.byteLength !== 12) {
        throw new CryptosuiteError(
          'CIPHER_MESSAGE_INVALID',
          'getParamsByAlgCode: expected a 96-bit IV for AES-CTR.'
        )
      }

      const counter = new Uint8Array(16)
      counter.set(iv)
      return {
        name: 'AES-CTR',
        counter,
        length: 32,
      }
    }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `getParamsByAlgCode: unsupported cipher JWK alg "${algCode}".`
  )
}
