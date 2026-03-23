import { CryptosuiteError } from '../../.errors/class.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import { normalizeSignJWK } from '../Signer/normalizeSignJWK/index.js'
import type { SignJWK } from '../Signer/types/index.js'
import { normalizeVerifyJWK } from '../Verifier/normalizeVerifyJWK/index.js'
import type { VerifyJWK } from '../Verifier/types/index.js'

export type DigitalSignatureAlgorithm =
  | 'Ed25519'
  | 'Ed448'
  | {
      name: 'ECDSA'
      namedCurve: string
      hash: string
      alg?: string
    }
  | {
      name: 'RSA-PSS'
      modulusLength: number
      publicExponent?: Uint8Array
      hash: string
      alg?: string
      saltLength?: number
    }
  | {
      name: 'RSASSA-PKCS1-v1_5'
      modulusLength: number
      publicExponent?: Uint8Array
      hash: string
      alg?: string
    }

function jwkAlgOf(a: DigitalSignatureAlgorithm): string {
  if (a === 'Ed25519' || a === 'Ed448') return 'EdDSA'
  if (a.alg) return a.alg
  if (a.name === 'ECDSA') {
    if (a.hash === 'SHA-256') return 'ES256'
    if (a.hash === 'SHA-384') return 'ES384'
    if (a.hash === 'SHA-512') return 'ES512'
    return 'ECDSA'
  }
  if (a.name === 'RSA-PSS') {
    if (a.hash === 'SHA-256') return 'PS256'
    if (a.hash === 'SHA-384') return 'PS384'
    if (a.hash === 'SHA-512') return 'PS512'
    return 'RSA-PSS'
  }
  if (a.hash === 'SHA-256') return 'RS256'
  if (a.hash === 'SHA-384') return 'RS384'
  if (a.hash === 'SHA-512') return 'RS512'
  return 'RSASSA-PKCS1-v1_5'
}

function digestLengthOf(hash: string): number | undefined {
  if (hash === 'SHA-1') return 20
  if (hash === 'SHA-256') return 32
  if (hash === 'SHA-384') return 48
  if (hash === 'SHA-512') return 64
  return undefined
}

function generateParamsOf(a: DigitalSignatureAlgorithm): AlgorithmIdentifier {
  if (a === 'Ed25519' || a === 'Ed448') return { name: a }
  if (a.name === 'ECDSA') return { name: 'ECDSA', namedCurve: a.namedCurve }
  return {
    name: a.name,
    modulusLength: a.modulusLength,
    publicExponent: a.publicExponent ?? new Uint8Array([1, 0, 1]),
    hash: { name: a.hash },
  }
}

export async function generateDigitalSignatureKeypair(
  algorithm: DigitalSignatureAlgorithm
): Promise<{
  signJwk: SignJWK
  verifyJwk: VerifyJWK
}> {
  assertSubtleAvailable('generateDigitalSignatureKeypair')

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
      'generateDigitalSignatureKeypair: selected algorithm is not supported by this WebCrypto runtime.'
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

  const signJwk = normalizeSignJWK({
    ...rawSign,
    alg,
    use: 'sig',
    ...(typeof algorithm === 'string'
      ? {}
      : algorithm.hash === undefined
        ? {}
        : { hash: algorithm.hash }),
    ...(typeof algorithm === 'string' || algorithm.name !== 'RSA-PSS'
      ? {}
      : algorithm.saltLength === undefined
        ? { saltLength: digestLengthOf(algorithm.hash) }
        : { saltLength: algorithm.saltLength }),
  })
  const verifyJwk = normalizeVerifyJWK({
    ...rawVerify,
    alg,
    use: 'sig',
    ...(typeof algorithm === 'string'
      ? {}
      : algorithm.hash === undefined
        ? {}
        : { hash: algorithm.hash }),
    ...(typeof algorithm === 'string' || algorithm.name !== 'RSA-PSS'
      ? {}
      : algorithm.saltLength === undefined
        ? { saltLength: digestLengthOf(algorithm.hash) }
        : { saltLength: algorithm.saltLength }),
  })

  return { signJwk, verifyJwk }
}
