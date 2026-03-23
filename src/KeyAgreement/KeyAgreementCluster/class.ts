import { DecapsulateJWKHarness } from '../Decapsulator/DecapuslateKeyHarness/class.js'
import type { DecapsulateJWK } from '../Decapsulator/types/index.js'
import { EncapsulateJWKHarness } from '../Encapsulator/EncapsulateKeyHarness/class.js'
import type { EncapsulateJWK } from '../Encapsulator/types/index.js'
import type { CipherJWK } from '../../Cipher/types/index.js'
import type {
  KeyAgreementArtifact,
  SharedKeyContext,
  SharedKeyJWK,
} from '../types/index.js'

export class KeyAgreementCluster {
  static #encapsulators = new WeakMap<
    EncapsulateJWK,
    WeakRef<EncapsulateJWKHarness>
  >()
  static #decapsulators = new WeakMap<
    DecapsulateJWK,
    WeakRef<DecapsulateJWKHarness>
  >()

  static #loadEncapsulator(
    encapsulateJwk: EncapsulateJWK
  ): EncapsulateJWKHarness {
    const weakRef = KeyAgreementCluster.#encapsulators.get(encapsulateJwk)
    let harness = weakRef?.deref()
    if (!harness) {
      harness = new EncapsulateJWKHarness(encapsulateJwk)
      KeyAgreementCluster.#encapsulators.set(
        encapsulateJwk,
        new WeakRef(harness)
      )
    }
    return harness
  }

  static #loadDecapsulator(
    decapsulateJwk: DecapsulateJWK
  ): DecapsulateJWKHarness {
    const weakRef = KeyAgreementCluster.#decapsulators.get(decapsulateJwk)
    let harness = weakRef?.deref()
    if (!harness) {
      harness = new DecapsulateJWKHarness(decapsulateJwk)
      KeyAgreementCluster.#decapsulators.set(
        decapsulateJwk,
        new WeakRef(harness)
      )
    }
    return harness
  }

  static async encapsulate(
    encapsulateJwk: EncapsulateJWK,
    context: SharedKeyContext = {}
  ): Promise<{ artifact: KeyAgreementArtifact; sharedJwk: SharedKeyJWK }> {
    return KeyAgreementCluster.#loadEncapsulator(encapsulateJwk).encapsulate(
      context
    )
  }

  static async decapsulate(
    artifact: KeyAgreementArtifact,
    decapsulateJwk: DecapsulateJWK,
    context: SharedKeyContext = {}
  ): Promise<{ sharedJwk: SharedKeyJWK }> {
    return KeyAgreementCluster.#loadDecapsulator(decapsulateJwk).decapsulate(
      artifact,
      context
    )
  }

  static async wrap(
    wrapJwk: EncapsulateJWK,
    cipherJwk: CipherJWK
  ): Promise<ArrayBuffer> {
    return KeyAgreementCluster.#loadEncapsulator(wrapJwk).wrap(cipherJwk)
  }

  static async unwrap(
    unwrapJwk: DecapsulateJWK,
    ciphertext: BufferSource
  ): Promise<CipherJWK> {
    return (await KeyAgreementCluster.#loadDecapsulator(unwrapJwk).unwrap(
      ciphertext
    )) as CipherJWK
  }
}
