import { fromBase64UrlString } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../../.errors/class.js'
import type { CipherAlgorithmName, CipherKey } from '../types/index.js'

export function getAlgorithmNameFromKey(key: Pick<JsonWebKey, 'alg'>): CipherAlgorithmName {
  switch (key.alg) {
    case 'A256CTR':
      return 'AES-CTR'
  }

  throw new CryptosuiteError(
    'ALGORITHM_UNSUPPORTED',
    `getAlgorithmNameFromKey: unsupported cipher JWK alg "${String(key.alg)}".`
  )
}

export function validateKeyByAlgorithmName(key: JsonWebKey): CipherKey {
  const candidate = key as JsonWebKey | null

  if (!candidate || typeof candidate !== 'object') {
    throw new CryptosuiteError(
      'CIPHER_KEY_INVALID',
      'validateKeyByAlgorithmName: expected a cipher JWK object.'
    )
  }

  switch (getAlgorithmNameFromKey(candidate)) {
    case 'AES-CTR': {
      if (candidate.alg !== 'A256CTR') {
        throw new CryptosuiteError(
          'ALGORITHM_UNSUPPORTED',
          `validateKeyByAlgorithmName: unsupported AES-CTR cipher JWK alg "${String(candidate.alg)}".`
        )
      }

      if (candidate.kty !== 'oct' || typeof candidate.k !== 'string') {
        throw new CryptosuiteError(
          'CIPHER_KEY_INVALID',
          'validateKeyByAlgorithmName: expected a symmetric AES-CTR cipher JWK.'
        )
      }

      if (candidate.use !== undefined && candidate.use !== 'enc') {
        throw new CryptosuiteError(
          'CIPHER_KEY_INVALID',
          'validateKeyByAlgorithmName: JWK.use must be "enc" when present.'
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
          'validateKeyByAlgorithmName: JWK.key_ops must only contain encrypt/decrypt.'
        )
      }

      let keyBytes: Uint8Array
      try {
        keyBytes = fromBase64UrlString(candidate.k)
      } catch {
        throw new CryptosuiteError(
          'BASE64URL_INVALID',
          'validateKeyByAlgorithmName: invalid base64url key material.'
        )
      }

      if (keyBytes.byteLength !== 32) {
        throw new CryptosuiteError(
          'CIPHER_KEY_INVALID',
          'validateKeyByAlgorithmName: key material must be 256 bits.'
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
}
