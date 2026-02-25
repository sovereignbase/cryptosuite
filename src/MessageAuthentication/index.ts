export { deriveHMACKey } from './deriveHMACKey/index.js'
export { generateHMACKey } from './generateHMACKey/index.js'
export { HMACAgent } from './HMACAgent/class.js'
export { HMACCluster } from './HMACCluster/class.js'
export type HMACJWK = JsonWebKey & {
  kty: 'oct'
  k: string
  alg?: 'HS256'
  use?: 'sig'
  key_ops?: ('sign' | 'verify')[]
}
