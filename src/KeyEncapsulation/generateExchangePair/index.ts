import { CryptosuiteError } from '../../.errors/class.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import type { UnwrapJWK, WrapJWK } from '../index.js'

export async function generateExchangePair(): Promise<{
  wrapJwk: WrapJWK
  unwrapJwk: UnwrapJWK
}> {
  assertSubtleAvailable('generateExchangePair')
  let exchangePair: CryptoKeyPair
  try {
    exchangePair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['wrapKey', 'unwrapKey']
    )
  } catch {
    throw new CryptosuiteError(
      'RSA_OAEP_UNSUPPORTED',
      'generateExchangePair: RSA-OAEP (4096/SHA-256) is not supported.'
    )
  }
  const wrapJwk = (await crypto.subtle.exportKey(
    'jwk',
    exchangePair.publicKey
  )) as WrapJWK
  const unwrapJwk = (await crypto.subtle.exportKey(
    'jwk',
    exchangePair.privateKey
  )) as UnwrapJWK
  return { wrapJwk, unwrapJwk }
}
