import { CryptosuiteError } from '../../.errors/class.js'
import { assertSubtleAvailable } from '../../.helpers/assertSubtleAvailable.js'
import { normalizeEncapsulateJWK } from '../Encapsulator/normalizeEncapsulateJWK/index.js'
import type { EncapsulateJWK } from '../Encapsulator/types/index.js'
import { normalizeDecapsulateJWK } from '../Decapsulator/normalizeDecapsulateJWK/index.js'
import type { DecapsulateJWK } from '../Decapsulator/types/index.js'

type CipherDeclaration = {
  cipherAlg: string
  ivLength?: number
  tagLength?: number
  counterLength?: number
}

type KeyAgreementPrimitive =
  | {
      name: 'RSA-OAEP'
      modulusLength: number
      publicExponent?: Uint8Array
      hash: string
      alg?: string
    }
  | {
      name: 'ECDH'
      namedCurve: string
      alg?: string
    }
  | {
      name: 'X25519'
      alg?: string
    }
  | {
      name: 'X448'
      alg?: string
    }

export type KeyAgreementAlgorithm = KeyAgreementPrimitive & CipherDeclaration

function jwkAlgOf(a: KeyAgreementAlgorithm): string {
  if (a.alg) return a.alg
  if (a.name === 'RSA-OAEP') {
    if (a.hash === 'SHA-1') return 'RSA-OAEP'
    if (a.hash === 'SHA-256') return 'RSA-OAEP-256'
    if (a.hash === 'SHA-384') return 'RSA-OAEP-384'
    if (a.hash === 'SHA-512') return 'RSA-OAEP-512'
    return 'RSA-OAEP'
  }
  return a.name
}

function rsaPublicExponentOf(
  a: Extract<KeyAgreementAlgorithm, { name: 'RSA-OAEP' }>
): Uint8Array {
  return a.publicExponent ?? new Uint8Array([1, 0, 1])
}

function generateParamsOf(
  a: KeyAgreementAlgorithm
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

function keyUsagesOf(a: KeyAgreementAlgorithm): KeyUsage[] {
  if (a.name === 'RSA-OAEP') return ['wrapKey', 'unwrapKey']
  return ['deriveKey', 'deriveBits']
}

export async function generateKeyAgreementKeypair(
  algorithm: KeyAgreementAlgorithm
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
    cipherAlg: algorithm.cipherAlg,
    use: 'enc',
    ...(algorithm.name === 'RSA-OAEP' ? { hash: algorithm.hash } : {}),
    ...(algorithm.ivLength === undefined ? {} : { ivLength: algorithm.ivLength }),
    ...(algorithm.tagLength === undefined ? {} : { tagLength: algorithm.tagLength }),
    ...(algorithm.counterLength === undefined
      ? {}
      : { counterLength: algorithm.counterLength }),
    key_ops: algorithm.name === 'RSA-OAEP' ? ['wrapKey'] : [],
  })

  const decapsulateJwk = normalizeDecapsulateJWK({
    ...rawUnwrap,
    alg,
    cipherAlg: algorithm.cipherAlg,
    use: 'enc',
    ...(algorithm.name === 'RSA-OAEP' ? { hash: algorithm.hash } : {}),
    ...(algorithm.ivLength === undefined ? {} : { ivLength: algorithm.ivLength }),
    ...(algorithm.tagLength === undefined ? {} : { tagLength: algorithm.tagLength }),
    ...(algorithm.counterLength === undefined
      ? {}
      : { counterLength: algorithm.counterLength }),
    key_ops:
      algorithm.name === 'RSA-OAEP'
        ? ['unwrapKey']
        : ['deriveKey', 'deriveBits'],
  })

  return { encapsulateJwk, decapsulateJwk }
}
