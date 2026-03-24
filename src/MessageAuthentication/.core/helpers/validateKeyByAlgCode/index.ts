import { fromBase64UrlString } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../../../.errors/class.js'
import type { MessageAuthenticationKey } from '../../types/index.js'

export function validateKeyByAlgCode(
  jwk: JsonWebKey
): MessageAuthenticationKey {
  const candidate = jwk as JsonWebKey | null

  if (!candidate || typeof candidate !== 'object') {
    throw new CryptosuiteError(
      'HMAC_JWK_INVALID',
      'validateKeyByAlgCode: expected a message authentication JWK object.'
    )
  }

  switch (candidate.alg) {
    case 'HS256': {
      if (candidate.kty !== 'oct' || typeof candidate.k !== 'string') {
        throw new CryptosuiteError(
          'HMAC_JWK_INVALID',
          'validateKeyByAlgCode: expected a symmetric message authentication JWK.'
        )
      }

      if (candidate.use !== undefined && candidate.use !== 'sig') {
        throw new CryptosuiteError(
          'HMAC_JWK_INVALID',
          'validateKeyByAlgCode: JWK.use must be "sig" when present.'
        )
      }

      if (
        candidate.key_ops !== undefined &&
        (!Array.isArray(candidate.key_ops) ||
          candidate.key_ops.some((operation) => {
            return operation !== 'sign' && operation !== 'verify'
          }))
      ) {
        throw new CryptosuiteError(
          'HMAC_JWK_INVALID',
          'validateKeyByAlgCode: JWK.key_ops must only contain sign/verify.'
        )
      }

      try {
        fromBase64UrlString(candidate.k)
      } catch {
        throw new CryptosuiteError(
          'BASE64URL_INVALID',
          'validateKeyByAlgCode: invalid base64url key material.'
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
        n: _n,
        e: _e,
        x: _x,
        y: _y,
        crv: _crv,
        alg: _alg,
        use: _use,
        key_ops: _keyOps,
        ...rest
      } = candidate

      return {
        ...rest,
        kty: 'oct',
        k: candidate.k,
        alg: candidate.alg,
        use: 'sig',
        key_ops:
          candidate.key_ops === undefined
            ? (['sign', 'verify'] as const)
            : ([...candidate.key_ops] as ('sign' | 'verify')[]),
      }
    }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `validateKeyByAlgCode: unsupported message authentication JWK alg "${String(candidate.alg)}"; expected HS256.`
  )
}
