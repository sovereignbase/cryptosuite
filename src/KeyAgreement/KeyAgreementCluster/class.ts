import { DecapsulateKeyHarness } from '../.core/DecapsulateKeyHarness/class.js'
import type { DecapsulateKey } from '../.core/types/index.js'
import { EncapsulateKeyHarness } from '../.core/EncapsulateKeyHarness/class.js'
import type { EncapsulateKey } from '../.core/types/index.js'
import type { CipherKey } from '../../CipherMessage/.core/types/index.js'
import type { KeyOffer } from '../.core/types/index.js'

export class KeyAgreementCluster {
  static #encapsulators = new WeakMap<
    EncapsulateKey,
    WeakRef<EncapsulateKeyHarness>
  >()
  static #decapsulators = new WeakMap<
    DecapsulateKey,
    WeakRef<DecapsulateKeyHarness>
  >()

  static #loadEncapsulator(
    encapsulateJwk: EncapsulateKey
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
    decapsulateKey: DecapsulateKey
  ): DecapsulateKeyHarness {
    const weakRef = KeyAgreementCluster.#decapsulators.get(decapsulateKey)
    let harness = weakRef?.deref()
    if (!harness) {
      harness = new DecapsulateKeyHarness(decapsulateKey)
      KeyAgreementCluster.#decapsulators.set(
        decapsulateKey,
        new WeakRef(harness)
      )
    }
    return harness
  }

  static async encapsulate(
    encapsulateKey: EncapsulateKey
  ): Promise<{ keyOffer: KeyOffer; cipherKey: CipherKey }> {
    return KeyAgreementCluster.#loadEncapsulator(encapsulateKey).encapsulate()
  }

  static async decapsulate(
    keyOffer: KeyOffer,
    decapsulateKey: DecapsulateKey
  ): Promise<{ cipherKey: CipherKey }> {
    return KeyAgreementCluster.#loadDecapsulator(decapsulateKey).decapsulate(
      keyOffer
    )
  }
}
