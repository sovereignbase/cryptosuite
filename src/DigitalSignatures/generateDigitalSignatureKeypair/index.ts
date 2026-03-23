import { CryptosuiteError } from '../../.errors/class.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import { normalizeSignJWK } from '../Signer/normalizeSignJWK/index.js'
import { SignJWK } from '../Signer/types/index.js'
import { normalizeVerifyJWK } from '../Verifier/normalizeVerifyJWK/index.js'
import { VerifyJWK } from '../Verifier/types/index.js'

type ECDSACurve = 'P-256' | 'P-384' | 'P-521'
type RsaHash = 'SHA-256' | 'SHA-384' | 'SHA-512'

export type Algorithms =
  | 'Ed25519'
  | { name: 'ECDSA'; namedCurve: ECDSACurve }
  | {
      name: 'RSA-PSS'
      modulusLength: 2048 | 3072 | 4096
      publicExponent?: Uint8Array
      hash: RsaHash
    }

function jwkAlgOf(a: Algorithms): string {
  if (a === 'Ed25519') return 'EdDSA'
  if (a.name === 'ECDSA') {
    if (a.namedCurve === 'P-256') return 'ES256'
    if (a.namedCurve === 'P-384') return 'ES384'
    return 'ES512'
  }
  if (a.hash === 'SHA-256') return 'PS256'
  if (a.hash === 'SHA-384') return 'PS384'
  return 'PS512'
}

function generateParamsOf(a: Algorithms): any {
  if (a === 'Ed25519') return { name: 'Ed25519' }
  if (a.name === 'ECDSA') return { name: 'ECDSA', namedCurve: a.namedCurve }
  return {
    name: 'RSA-PSS',
    modulusLength: a.modulusLength,
    publicExponent: a.publicExponent ?? new Uint8Array([1, 0, 1]),
    hash: { name: a.hash },
  }
}

export async function generateDigitalSignatureCryptoKeyPair(
  algorithm: Algorithms
): Promise<{
  signJwk: SignJWK
  verifyJwk: VerifyJWK
}> {
  assertSubtleAvailable('generateDigitalSignatureCryptoKeyPair')

  const alg = jwkAlgOf(algorithm)

  let pair: CryptoKeyPair
  try {
    pair = (await crypto.subtle.generateKey(generateParamsOf(algorithm), true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
  } catch {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'generateDigitalSignatureCryptoKeyPair: selected algorithm is not supported by this WebCrypto runtime.'
    )
  }

  const rawSign = (await crypto.subtle.exportKey(
    'jwk',
    pair.privateKey
  )) as JsonWebKey
  const rawVerify = (await crypto.subtle.exportKey(
    'jwk',
    pair.publicKey
  )) as JsonWebKey

  const signJwk = normalizeSignJWK({ ...rawSign, alg })
  const verifyJwk = normalizeVerifyJWK({ ...rawVerify, alg })

  return { signJwk, verifyJwk }
}
