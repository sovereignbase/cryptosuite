import { ed25519 } from '@noble/curves/ed25519.js'
import {
  combineSigners,
  ecSigner,
  ml_kem768_x25519,
} from '@noble/post-quantum/hybrid.js'
import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { toBase64UrlString } from '@sovereignbase/bytecodec'

const ed25519MlDsa65 = combineSigners(
  undefined,
  (seed) => seed,
  ecSigner(ed25519),
  ml_dsa65
)

export function bytes(...values) {
  return Uint8Array.from(values)
}

export function filledBytes(length, fill = 0) {
  return new Uint8Array(length).fill(fill)
}

export function createA256CtrKey(overrides = {}) {
  return {
    kty: 'oct',
    k: toBase64UrlString(filledBytes(32, 1)),
    alg: 'A256CTR',
    use: 'enc',
    key_ops: ['encrypt', 'decrypt'],
    ...overrides,
  }
}

export function createHs256Key(overrides = {}) {
  return {
    kty: 'oct',
    k: toBase64UrlString(filledBytes(32, 2)),
    alg: 'HS256',
    use: 'sig',
    key_ops: ['sign', 'verify'],
    ...overrides,
  }
}

export function createMlKemPublicKey(overrides = {}) {
  return {
    kty: 'AKP',
    alg: 'ML-KEM-1024',
    x: toBase64UrlString(filledBytes(ml_kem1024.lengths.publicKey, 3)),
    use: 'enc',
    key_ops: [],
    ...overrides,
  }
}

export function createMlKemPrivateKey(overrides = {}) {
  return {
    kty: 'AKP',
    alg: 'ML-KEM-1024',
    d: toBase64UrlString(filledBytes(ml_kem1024.lengths.secretKey, 4)),
    use: 'enc',
    key_ops: ['deriveKey', 'deriveBits'],
    ...overrides,
  }
}

export function createMlDsaSignKey(overrides = {}) {
  return {
    kty: 'AKP',
    alg: 'ML-DSA-87',
    d: toBase64UrlString(filledBytes(ml_dsa87.lengths.secretKey, 5)),
    use: 'sig',
    key_ops: ['sign'],
    ...overrides,
  }
}

export function createMlDsaVerifyKey(overrides = {}) {
  return {
    kty: 'AKP',
    alg: 'ML-DSA-87',
    x: toBase64UrlString(filledBytes(ml_dsa87.lengths.publicKey, 6)),
    use: 'sig',
    key_ops: ['verify'],
    ...overrides,
  }
}

export function createX25519MlKem768PublicKey(overrides = {}) {
  return {
    kty: 'AKP',
    alg: 'X25519-ML-KEM-768',
    x: toBase64UrlString(filledBytes(ml_kem768_x25519.lengths.publicKey, 7)),
    use: 'enc',
    key_ops: [],
    ...overrides,
  }
}

export function createX25519MlKem768PrivateKey(overrides = {}) {
  return {
    kty: 'AKP',
    alg: 'X25519-ML-KEM-768',
    d: toBase64UrlString(filledBytes(ml_kem768_x25519.lengths.secretKey, 8)),
    use: 'enc',
    key_ops: ['deriveKey', 'deriveBits'],
    ...overrides,
  }
}

export function createEd25519MlDsa65SignKey(overrides = {}) {
  return {
    kty: 'AKP',
    alg: 'Ed25519-ML-DSA-65',
    d: toBase64UrlString(filledBytes(ed25519MlDsa65.lengths.secretKey, 9)),
    use: 'sig',
    key_ops: ['sign'],
    ...overrides,
  }
}

export function createEd25519MlDsa65VerifyKey(overrides = {}) {
  return {
    kty: 'AKP',
    alg: 'Ed25519-ML-DSA-65',
    x: toBase64UrlString(filledBytes(ed25519MlDsa65.lengths.publicKey, 10)),
    use: 'sig',
    key_ops: ['verify'],
    ...overrides,
  }
}
