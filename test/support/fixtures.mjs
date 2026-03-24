import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { toBase64UrlString } from '@sovereignbase/bytecodec'

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
