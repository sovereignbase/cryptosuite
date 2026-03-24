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
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { CryptosuiteError } from '../../../../.errors/class.js'
import type { DecapsulateKey, EncapsulateKey } from '../../types/index.js'

export function createImportKeyAlgorithmByAlgCode(
  algCode: EncapsulateKey['alg'] | DecapsulateKey['alg']
): typeof ml_kem1024 {
  switch (algCode) {
    case 'ML-KEM-1024':
      return ml_kem1024
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `createImportKeyAlgorithmByAlgCode: unsupported key agreement alg "${algCode}".`
  )
}
