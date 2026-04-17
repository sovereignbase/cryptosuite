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
import { createImportKeyAlgorithmByAlgCode } from '../createImportKeyAlgorithmByAlgCode/index.js'
import type { SignKey, VerifyKey } from '../../types/index.js'

export function validateKeyByAlgCode(key: JsonWebKey): SignKey | VerifyKey {
  const candidate = key as JsonWebKey | null

  if (!candidate || typeof candidate !== 'object') {
    throw new CryptosuiteError(
      'SIGN_JWK_INVALID',
      'validateKeyByAlgCode: expected a digital signature JWK object.'
    )
  }

  switch (candidate.alg) {
    case 'ML-DSA-87':
    case 'Ed25519-ML-DSA-65': {
      const algorithm = createImportKeyAlgorithmByAlgCode(candidate.alg)
      if (candidate.kty !== 'AKP') {
        throw new CryptosuiteError(
          'SIGN_JWK_INVALID',
          `validateKeyByAlgCode: expected an ${candidate.alg} digital signature JWK.`
        )
      }

      if (candidate.use !== undefined && candidate.use !== 'sig') {
        throw new CryptosuiteError(
          'SIGN_JWK_INVALID',
          'validateKeyByAlgCode: JWK.use must be "sig" when present.'
        )
      }

      if (typeof candidate.d === 'string') {
        if (
          candidate.key_ops !== undefined &&
          (!Array.isArray(candidate.key_ops) ||
            candidate.key_ops.length !== 1 ||
            candidate.key_ops[0] !== 'sign')
        ) {
          throw new CryptosuiteError(
            'SIGN_JWK_INVALID',
            'validateKeyByAlgCode: private JWK.key_ops must be ["sign"] when present.'
          )
        }

        let secretKey: Uint8Array
        try {
          secretKey = fromBase64UrlString(candidate.d)
        } catch {
          throw new CryptosuiteError(
            'BASE64URL_INVALID',
            'validateKeyByAlgCode: invalid base64url private key material.'
          )
        }

        if (secretKey.byteLength !== algorithm.lengths.secretKey) {
          throw new CryptosuiteError(
            'SIGN_JWK_INVALID',
            'validateKeyByAlgCode: private key material has invalid length.'
          )
        }

        const {
          x: _x,
          p: _p,
          q: _q,
          dp: _dp,
          dq: _dq,
          qi: _qi,
          k: _k,
          alg: _alg,
          use: _use,
          key_ops: _keyOps,
          ...rest
        } = candidate

        return {
          ...rest,
          kty: 'AKP',
          alg: candidate.alg,
          d: candidate.d,
          use: 'sig',
          key_ops: ['sign'] as const,
        }
      }

      if (typeof candidate.x === 'string') {
        if (
          candidate.key_ops !== undefined &&
          (!Array.isArray(candidate.key_ops) ||
            candidate.key_ops.length !== 1 ||
            candidate.key_ops[0] !== 'verify')
        ) {
          throw new CryptosuiteError(
            'VERIFY_JWK_INVALID',
            'validateKeyByAlgCode: public JWK.key_ops must be ["verify"] when present.'
          )
        }

        let publicKey: Uint8Array
        try {
          publicKey = fromBase64UrlString(candidate.x)
        } catch {
          throw new CryptosuiteError(
            'BASE64URL_INVALID',
            'validateKeyByAlgCode: invalid base64url public key material.'
          )
        }

        if (publicKey.byteLength !== algorithm.lengths.publicKey) {
          throw new CryptosuiteError(
            'VERIFY_JWK_INVALID',
            'validateKeyByAlgCode: public key material has invalid length.'
          )
        }

        const {
          d: _d,
          p: _p,
          q: _q,
          dp: _dp,
          dq: _dq,
          qi: _qi,
          k: _k,
          alg: _alg,
          use: _use,
          key_ops: _keyOps,
          ...rest
        } = candidate

        return {
          ...rest,
          kty: 'AKP',
          alg: candidate.alg,
          x: candidate.x,
          use: 'sig',
          key_ops: ['verify'] as const,
        }
      }

      throw new CryptosuiteError(
        'SIGN_JWK_INVALID',
        'validateKeyByAlgCode: expected either public x or private d key material.'
      )
    }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `validateKeyByAlgCode: unsupported digital signature JWK alg "${String(candidate.alg)}".`
  )
}
