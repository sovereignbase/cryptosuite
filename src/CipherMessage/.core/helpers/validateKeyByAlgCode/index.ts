import { fromBase64UrlString } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../../../.errors/class.js'
import type { CipherKey } from '../../types/index.js'

export function validateKeyByAlgCode(key: JsonWebKey): CipherKey {
  const candidate = key as JsonWebKey | null

  if (!candidate || typeof candidate !== 'object') {
    throw new CryptosuiteError(
      'CIPHER_KEY_INVALID',
      'validateKeyByAlgCode: expected a cipher JWK object.'
    )
  }

  switch (candidate.alg) {
    case 'A256CTR': {
      if (candidate.kty !== 'oct' || typeof candidate.k !== 'string') {
        throw new CryptosuiteError(
          'CIPHER_KEY_INVALID',
          'validateKeyByAlgCode: expected a symmetric cipher JWK.'
        )
      }

      if (candidate.use !== undefined && candidate.use !== 'enc') {
        throw new CryptosuiteError(
          'CIPHER_KEY_INVALID',
          'validateKeyByAlgCode: JWK.use must be "enc" when present.'
        )
      }

      if (
        candidate.key_ops !== undefined &&
        (!Array.isArray(candidate.key_ops) ||
          candidate.key_ops.some((operation) => {
            return operation !== 'encrypt' && operation !== 'decrypt'
          }))
      ) {
        throw new CryptosuiteError(
          'CIPHER_KEY_INVALID',
          'validateKeyByAlgCode: JWK.key_ops must only contain encrypt/decrypt.'
        )
      }

      let keyBytes: Uint8Array
      try {
        keyBytes = fromBase64UrlString(candidate.k)
      } catch {
        throw new CryptosuiteError(
          'BASE64URL_INVALID',
          'validateKeyByAlgCode: invalid base64url key material.'
        )
      }

      if (keyBytes.byteLength !== 32) {
        throw new CryptosuiteError(
          'CIPHER_KEY_INVALID',
          'validateKeyByAlgCode: key material must be 256 bits.'
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
        alg: 'A256CTR',
        use: 'enc',
        key_ops:
          candidate.key_ops === undefined
            ? (['encrypt', 'decrypt'] as const)
            : ([...candidate.key_ops] as ('encrypt' | 'decrypt')[]),
      }
    }
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `validateKeyByAlgCode: unsupported cipher JWK alg "${String(candidate.alg)}".`
  )
}
