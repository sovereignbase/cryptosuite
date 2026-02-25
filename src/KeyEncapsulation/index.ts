export { generateExchangePair } from './generateExchangePair/index.js'
export { WrapAgent } from './WrapAgent/class.js'
export { UnwrapAgent } from './UnwrapAgent/class.js'
export { ExchangeCluster } from './ExchangeCluster/class.js'
export type WrapJWK = JsonWebKey & {
  kty: 'RSA'
  n: string
  e: string
  alg?: 'RSA-OAEP-256'
  use?: 'enc'
  key_ops?: ('wrapKey' | 'encrypt')[]
  d?: never
  p?: never
  q?: never
  dp?: never
  dq?: never
  qi?: never
}

export type UnwrapJWK = JsonWebKey & {
  kty: 'RSA'
  n: string
  e: string
  d: string
  p?: string
  q?: string
  dp?: string
  dq?: string
  qi?: string
  alg?: 'RSA-OAEP-256'
  use?: 'enc'
  key_ops?: ('unwrapKey' | 'decrypt')[]
}
