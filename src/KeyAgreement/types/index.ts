import type { CipherJWK } from '../../Cipher/types/index.js'
import type { HMACJWK } from '../../MessageAuthentication/index.js'
import type { EncapsulateJWK } from '../Encapsulator/types/index.js'

export type SharedKeyContext =
  | { kind?: 'cipher'; alg?: 'A256GCM' }
  | { kind: 'messageAuthentication'; alg?: 'HS256' }

export type SharedKeyJWK = CipherJWK | HMACJWK

export type KeyAgreementArtifact =
  | {
      kind: 'wrapKey'
      ciphertext: ArrayBuffer
    }
  | {
      kind: 'deriveKey'
      ephemeralPublicJwk: EncapsulateJWK
    }
