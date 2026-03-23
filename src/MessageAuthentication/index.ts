export { deriveHMACKey } from './deriveHMACKey/index.js'
export { generateHMACKey } from './generateHMACKey/index.js'
export { normalizeHMACJWK } from './normalizeHMACJWK/index.js'
export { HMACAgent } from './HMACKeyHarness/class.js'
export { HMACCluster } from './HMACCluster/class.js'
export type HMACJWK = JsonWebKey & {
  kty: 'oct'
  k: string
  alg?: 'HS256'
  use?: 'sig'
  key_ops?: ('sign' | 'verify')[]
}
