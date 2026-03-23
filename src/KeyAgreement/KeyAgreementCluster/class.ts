import { DecapsulateKeyHarness } from '../Decapsulator/DecapsulateKeyHarness/class.js'
import type { DecapsulateJWK } from '../Decapsulator/types/index.js'
import { EncapsulateKeyHarness } from '../Encapsulator/EncapsulateKeyHarness/class.js'
import type { EncapsulateJWK } from '../Encapsulator/types/index.js'
import type { CipherJWK } from '../../CipherMessage/types/index.js'
import type { KeyAgreementArtifact } from '../types/index.js'

export class KeyAgreementCluster {
  static #encapsulators = new WeakMap<
    EncapsulateJWK,
    WeakRef<EncapsulateKeyHarness>
  >()
  static #decapsulators = new WeakMap<
    DecapsulateJWK,
    WeakRef<DecapsulateKeyHarness>
  >()

  static #loadEncapsulator(
    encapsulateJwk: EncapsulateJWK
  ): EncapsulateKeyHarness {
    const weakRef = KeyAgreementCluster.#encapsulators.get(encapsulateJwk)
    let harness = weakRef?.deref()
    if (!harness) {
      harness = new EncapsulateKeyHarness(encapsulateJwk)
      KeyAgreementCluster.#encapsulators.set(
        encapsulateJwk,
        new WeakRef(harness)
      )
    }
    return harness
  }

  static #loadDecapsulator(
    decapsulateJwk: DecapsulateJWK
  ): DecapsulateKeyHarness {
    const weakRef = KeyAgreementCluster.#decapsulators.get(decapsulateJwk)
    let harness = weakRef?.deref()
    if (!harness) {
      harness = new DecapsulateKeyHarness(decapsulateJwk)
      KeyAgreementCluster.#decapsulators.set(
        decapsulateJwk,
        new WeakRef(harness)
      )
    }
    return harness
  }

  static async encapsulate(
    encapsulateJwk: EncapsulateJWK
  ): Promise<{ artifact: KeyAgreementArtifact; cipherJwk: CipherJWK }> {
    return KeyAgreementCluster.#loadEncapsulator(encapsulateJwk).encapsulate()
  }

  static async decapsulate(
    artifact: KeyAgreementArtifact,
    decapsulateJwk: DecapsulateJWK
  ): Promise<{ cipherJwk: CipherJWK }> {
    return KeyAgreementCluster.#loadDecapsulator(decapsulateJwk).decapsulate(artifact)
  }
}
