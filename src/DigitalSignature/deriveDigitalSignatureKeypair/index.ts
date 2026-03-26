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
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { CryptosuiteError } from '../../.errors/class.js'
import { getBufferSourceLength } from '../../.helpers/getBufferSourceLength.js'
import { validateKeyByAlgCode } from '../.core/helpers/validateKeyByAlgCode/index.js'
import type { SignKey, VerifyKey } from '../.core/types/index.js'

/**
 * Deterministically derives a digital signature key pair from source key material.
 *
 * @param sourceKeyMaterial - The source bytes to derive from.
 * @returns The derived private signing key and public verification key.
 */
export async function deriveDigitalSignatureKeypair(
  sourceKeyMaterial: Uint8Array
): Promise<{
  signKey: SignKey
  verifyKey: VerifyKey
}> {
  if (
    getBufferSourceLength(
      sourceKeyMaterial,
      'deriveDigitalSignatureKeypair'
    ) !== ml_dsa87.lengths.seed
  ) {
    throw new CryptosuiteError(
      'SIGN_JWK_INVALID',
      `deriveDigitalSignatureKeypair: source key material must be exactly ${ml_dsa87.lengths.seed} bytes.`
    )
  }

  const { publicKey, secretKey } = ml_dsa87.keygen(sourceKeyMaterial)
  const signKey = validateKeyByAlgCode({
    kty: 'AKP',
    alg: 'ML-DSA-87',
    d: toBase64UrlString(secretKey),
    use: 'sig',
    key_ops: ['sign'],
  })
  const verifyKey = validateKeyByAlgCode({
    kty: 'AKP',
    alg: 'ML-DSA-87',
    x: toBase64UrlString(publicKey),
    use: 'sig',
    key_ops: ['verify'],
  })

  return {
    signKey: signKey as SignKey,
    verifyKey: verifyKey as VerifyKey,
  }
}
