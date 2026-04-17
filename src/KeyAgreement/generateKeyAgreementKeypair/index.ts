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
import { toBase64UrlString } from '@sovereignbase/bytecodec'
import { createImportKeyAlgorithmByAlgCode } from '../.core/helpers/createImportKeyAlgorithmByAlgCode/index.js'
import { validateKeyByAlgCode } from '../.core/helpers/validateKeyByAlgCode/index.js'
import type { EncapsulateKey, DecapsulateKey } from '../.core/types/index.js'

/**
 * Generates a new key agreement key pair.
 *
 * @returns The generated public and private key agreement keys.
 */
export async function generateKeyAgreementKeypair(): Promise<{
  encapsulateKey: EncapsulateKey
  decapsulateKey: DecapsulateKey
}> {
  const { publicKey, secretKey } =
    createImportKeyAlgorithmByAlgCode('X25519-ML-KEM-768').keygen()
  const encapsulateKey = validateKeyByAlgCode({
    kty: 'AKP',
    alg: 'X25519-ML-KEM-768',
    x: toBase64UrlString(publicKey),
    use: 'enc',
    key_ops: [],
  })
  const decapsulateKey = validateKeyByAlgCode({
    kty: 'AKP',
    alg: 'X25519-ML-KEM-768',
    d: toBase64UrlString(secretKey),
    use: 'enc',
    key_ops: ['deriveKey', 'deriveBits'],
  })

  return {
    encapsulateKey: encapsulateKey as EncapsulateKey,
    decapsulateKey: decapsulateKey as DecapsulateKey,
  }
}
