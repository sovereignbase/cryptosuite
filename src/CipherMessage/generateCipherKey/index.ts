import { CryptosuiteError } from '../../.errors/class.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import { normalizeCipherJWK } from '../normalizeCipherJWK/index.js'
import type { CipherJWK, CipherMessageAlgorithm } from '../types/index.js'

function jwkAlgOf(algorithm: CipherMessageAlgorithm): string {
  if (algorithm.alg) return algorithm.alg
  const mode = algorithm.name.replace('AES-', '')
  return `A${algorithm.length}${mode}`
}

export async function generateCipherKey(
  algorithm: CipherMessageAlgorithm = { name: 'AES-GCM', length: 256 }
): Promise<CipherJWK> {
  assertSubtleAvailable('generateCipherKey')
  let aesKey: CryptoKey
  try {
    aesKey = await crypto.subtle.generateKey(
      { name: algorithm.name, length: algorithm.length },
      true,
      ['encrypt', 'decrypt']
    )
  } catch {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'generateCipherKey: selected cipher algorithm is not supported by this WebCrypto runtime.'
    )
  }

  return normalizeCipherJWK({
    ...(await crypto.subtle.exportKey('jwk', aesKey)),
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
