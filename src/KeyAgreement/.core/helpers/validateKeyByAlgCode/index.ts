import { fromBase64UrlString } from '@sovereignbase/bytecodec'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { CryptosuiteError } from '../../../../.errors/class.js'
import type { DecapsulateKey, EncapsulateKey } from '../../types/index.js'

export function validateKeyByAlgCode(
  key: JsonWebKey
): EncapsulateKey | DecapsulateKey {
  const candidate = key as JsonWebKey | null

  if (!candidate || typeof candidate !== 'object') {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_KEY_INVALID',
      'validateKeyByAlgCode: expected a key agreement JWK object.'
    )
  }

  switch (candidate.alg) {
    case 'ML-KEM-1024': {
      if (candidate.kty !== 'AKP') {
        throw new CryptosuiteError(
          'KEY_AGREEMENT_KEY_INVALID',
          'validateKeyByAlgCode: expected an ML-KEM-1024 key agreement JWK.'
        )
      }

      if (candidate.use !== undefined && candidate.use !== 'enc') {
        throw new CryptosuiteError(
          'KEY_AGREEMENT_KEY_INVALID',
          'validateKeyByAlgCode: JWK.use must be "enc" when present.'
        )
      }

      if (typeof candidate.d === 'string') {
        if (
          candidate.key_ops !== undefined &&
          (!Array.isArray(candidate.key_ops) ||
            candidate.key_ops.some((operation) => {
              return operation !== 'deriveKey' && operation !== 'deriveBits'
            }))
        ) {
          throw new CryptosuiteError(
            'KEY_AGREEMENT_KEY_INVALID',
            'validateKeyByAlgCode: private JWK.key_ops must only contain deriveKey/deriveBits.'
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

        if (secretKey.byteLength !== ml_kem1024.lengths.secretKey) {
          throw new CryptosuiteError(
            'KEY_AGREEMENT_KEY_INVALID',
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
          oth: _oth,
          k: _k,
          alg: _alg,
          use: _use,
          key_ops: _keyOps,
          ...rest
        } = candidate

        return {
          ...rest,
          kty: 'AKP',
          alg: 'ML-KEM-1024',
          d: candidate.d,
          use: 'enc',
          key_ops:
            candidate.key_ops === undefined
              ? (['deriveKey', 'deriveBits'] as const)
              : ([...candidate.key_ops] as ('deriveKey' | 'deriveBits')[]),
        }
      }

      if (typeof candidate.x === 'string') {
        if (
          candidate.key_ops !== undefined &&
          (!Array.isArray(candidate.key_ops) || candidate.key_ops.length !== 0)
        ) {
          throw new CryptosuiteError(
            'KEY_AGREEMENT_KEY_INVALID',
            'validateKeyByAlgCode: public JWK.key_ops must be [] when present.'
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

        if (publicKey.byteLength !== ml_kem1024.lengths.publicKey) {
          throw new CryptosuiteError(
            'KEY_AGREEMENT_KEY_INVALID',
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
          oth: _oth,
          k: _k,
          alg: _alg,
          use: _use,
          key_ops: _keyOps,
          ...rest
        } = candidate

        return {
          ...rest,
          kty: 'AKP',
          alg: 'ML-KEM-1024',
          x: candidate.x,
          use: 'enc',
          key_ops: [] as const,
        }
      }

      throw new CryptosuiteError(
        'KEY_AGREEMENT_KEY_INVALID',
        'validateKeyByAlgCode: expected either public x or private d key material.'
      )
    }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `validateKeyByAlgCode: unsupported key agreement JWK alg "${String(candidate.alg)}".`
  )
}
