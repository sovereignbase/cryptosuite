import { toBufferSource } from '@sovereignbase/bytecodec'
import { CryptosuiteError } from '../../.errors/class.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import { getBufferSourceLength } from '../../.helpers/getBufferSourceLength.js'
import { normalizeCipherJWK } from '../normalizeCipherJWK/index.js'
import type { CipherJWK, CipherMessageAlgorithm } from '../types/index.js'

function jwkAlgOf(algorithm: CipherMessageAlgorithm): string {
  if (algorithm.alg) return algorithm.alg
  const mode = algorithm.name.replace('AES-', '')
  return `A${algorithm.length}${mode}`
}

export async function deriveCipherKey(
  rawKey: Uint8Array,
  algorithm: CipherMessageAlgorithm = { name: 'AES-GCM', length: 256 }
): Promise<CipherJWK> {
  assertSubtleAvailable('deriveCipherKey')
  if (getBufferSourceLength(rawKey, 'deriveCipherKey') * 8 !== algorithm.length) {
    throw new CryptosuiteError(
      'CIPHER_JWK_INVALID',
      'deriveCipherKey: raw key material length does not match the declared algorithm length.'
    )
  }
  let key: CryptoKey
  try {
    key = await crypto.subtle.importKey(
      'raw',
      toBufferSource(rawKey),
      { name: algorithm.name },
      true,
      ['encrypt', 'decrypt']
    )
  } catch {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'deriveCipherKey: selected cipher algorithm is not supported by this WebCrypto runtime.'
    )
  }

  return normalizeCipherJWK({
    ...(await crypto.subtle.exportKey('jwk', key)),
    alg: jwkAlgOf(algorithm),
    ...(algorithm.ivLength === undefined ? {} : { ivLength: algorithm.ivLength }),
    ...(algorithm.name !== 'AES-GCM' || algorithm.tagLength === undefined
      ? {}
      : { tagLength: algorithm.tagLength }),
    ...(algorithm.name !== 'AES-CTR' || algorithm.counterLength === undefined
      ? {}
      : { counterLength: algorithm.counterLength }),
  })
}
