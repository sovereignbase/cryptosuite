export { generateVerificationPair } from './generateVerificationPair/index.js'
export { SignAgent } from './SignAgent/class.js'
export { VerifyAgent } from '../Verifier/VerifyKeyHarness/class.js'
export { VerificationCluster } from './VerificationCluster/class.js'
export type SignJWK = JsonWebKey & {
  kty: 'OKP'
  crv: 'Ed25519'
  x: string
  d: string
  alg?: 'EdDSA'
  use?: 'sig'
  key_ops?: 'sign'[]
}

export type VerifyJWK = JsonWebKey & {
  kty: 'OKP'
  crv: 'Ed25519'
  x: string
  alg?: 'EdDSA'
  use?: 'sig'
  key_ops?: 'verify'[]
  d?: never
}
