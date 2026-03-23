import { CryptosuiteError } from '../../.errors/class.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import { normalizeEncapsulateJWK } from '../Encapsulator/normalizeEncapsulateJWK/index.js'
import type { EncapsulateJWK } from '../Encapsulator/types/index.js'
import { normalizeDecapsulateJWK } from '../Decapsulator/normalizeDecapsulateJWK/index.js'
import type { DecapsulateJWK } from '../Decapsulator/types/index.js'

type RsaOaepHash = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'
type ECDHCurve = 'P-256' | 'P-384' | 'P-521'
type EcdhJwkAlg =
  | 'ECDH-ES'
  | 'ECDH-ES+A128KW'
  | 'ECDH-ES+A192KW'
  | 'ECDH-ES+A256KW'

type RsaPublicExponent = Uint8Array<ArrayBuffer>

export type Algorithms =
  | {
      name: 'RSA-OAEP'
      modulusLength: 2048 | 3072 | 4096
      publicExponent?: RsaPublicExponent
      hash: RsaOaepHash
    }
  | {
      name: 'ECDH'
      namedCurve: ECDHCurve
      alg?: EcdhJwkAlg
    }
  | {
      name: 'X25519'
      alg?: EcdhJwkAlg
    }
  | {
      name: 'X448'
      alg?: EcdhJwkAlg
    }

function jwkAlgOf(a: Algorithms): string {
  if (a.name === 'RSA-OAEP') {
    if (a.hash === 'SHA-1') return 'RSA-OAEP'
    if (a.hash === 'SHA-256') return 'RSA-OAEP-256'
    if (a.hash === 'SHA-384') return 'RSA-OAEP-384'
    return 'RSA-OAEP-512'
  }
  return a.alg ?? 'ECDH-ES'
}

function rsaPublicExponentOf(
  a: Extract<Algorithms, { name: 'RSA-OAEP' }>
): Uint8Array<ArrayBuffer> {
  return (
    a.publicExponent ?? (new Uint8Array([1, 0, 1]) as Uint8Array<ArrayBuffer>)
  )
}

function generateParamsOf(
  a: Algorithms
): RsaHashedKeyGenParams | EcKeyGenParams | AlgorithmIdentifier {
  if (a.name === 'RSA-OAEP') {
    return {
      name: 'RSA-OAEP',
      modulusLength: a.modulusLength,
      publicExponent: rsaPublicExponentOf(a),
      hash: { name: a.hash },
    }
  }

  if (a.name === 'ECDH') {
    return {
      name: 'ECDH',
      namedCurve: a.namedCurve,
    }
  }

  return { name: a.name } as AlgorithmIdentifier
}

function keyUsagesOf(a: Algorithms): KeyUsage[] {
  if (a.name === 'RSA-OAEP') return ['wrapKey', 'unwrapKey']
  return ['deriveKey', 'deriveBits']
}

export async function generateKeyAgreementKeypair(
  algorithm: Algorithms
): Promise<{
  encapsulateJwk: EncapsulateJWK
  decapsulateJwk: DecapsulateJWK
}> {
  assertSubtleAvailable('generateKeyAgreementKeypair')

  const alg = jwkAlgOf(algorithm)

  let pair: CryptoKeyPair
  try {
    pair = (await crypto.subtle.generateKey(
      generateParamsOf(algorithm),
      true,
      keyUsagesOf(algorithm)
    )) as CryptoKeyPair
  } catch {
    throw new CryptosuiteError(
      'ALGORITHM_UNSUPPORTED',
      'generateKeyAgreementKeypair: selected algorithm is not supported by this WebCrypto runtime.'
    )
  }

  const rawWrap = (await crypto.subtle.exportKey(
    'jwk',
    pair.publicKey
  )) as JsonWebKey
  const rawUnwrap = (await crypto.subtle.exportKey(
    'jwk',
    pair.privateKey
  )) as JsonWebKey

  const encapsulateJwk = normalizeEncapsulateJWK({
    ...rawWrap,
    alg,
    use: 'enc',
    key_ops: algorithm.name === 'RSA-OAEP' ? ['wrapKey'] : [],
  })

  const decapsulateJwk = normalizeDecapsulateJWK({
    ...rawUnwrap,
    alg,
    use: 'enc',
    key_ops:
      algorithm.name === 'RSA-OAEP'
        ? ['unwrapKey']
        : ['deriveKey', 'deriveBits'],
  })

  return { encapsulateJwk, decapsulateJwk }
}
