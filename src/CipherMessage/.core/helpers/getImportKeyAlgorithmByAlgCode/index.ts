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
import type { CipherKey } from '../../types/index.js'
export function getImportKeyAlgorithmByAlgCode(
  algCode: CipherKey['alg']
): AlgorithmIdentifier {
  switch (algCode) {
    case 'A256CTR':
      return {
        name: 'AES-CTR',
      }
    case 'A256GCM':
      return {
        name: 'AES-GCM',
      }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `getImportKeyAlgorithmByAlgCode: unsupported cipher JWK alg "${algCode}".`
  )
}
