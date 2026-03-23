import { Signer } from '../Signer/class.js'
import type { SignJWK } from '../Signer/types/index.js'
import { Verifier } from '../Verifier/class.js'
import type { VerifyJWK } from '../Verifier/types/index.js'

export class DigitalSignatureCluster {
  static async sign(signJwk: SignJWK, bytes: Uint8Array): Promise<Uint8Array> {
    return Signer.sign(signJwk, bytes)
  }

  static async verify(
    verifyJwk: VerifyJWK,
    bytes: Uint8Array,
    signature: Uint8Array
  ): Promise<boolean> {
    return Verifier.verify(verifyJwk, bytes, signature)
  }
}
