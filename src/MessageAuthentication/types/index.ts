export type HMACJWK = JsonWebKey & {
  kty: 'oct'
  k: string
  alg?: string
  use?: 'sig'
  key_ops?: ('sign' | 'verify')[]
  hash?: string
}
