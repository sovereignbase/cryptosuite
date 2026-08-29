import { DecapsulateKeyHarness } from '../.core/DecapsulateKeyHarness/class.js'
import type { DecapsulateKey } from '../.core/types/index.js'
import { EncapsulateKeyHarness } from '../.core/EncapsulateKeyHarness/class.js'
import type { EncapsulateKey } from '../.core/types/index.js'
import type { CipherKey } from '../../CipherMessage/.core/types/index.js'
import type { KeyOffer } from '../.core/types/index.js'

/**
 * Routes key agreement operations through cached harness instances.
 */
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

  /**
   * Encapsulates a shared cipher key for the provided public key agreement key.
   *
   * @param encapsulateKey - The public key agreement key.
   * @returns The key offer and the locally reconstructed cipher key.
   */
  static async encapsulate(
    encapsulateKey: EncapsulateKey
  ): Promise<{ keyOffer: KeyOffer; cipherKey: CipherKey }> {
    return KeyAgreementCluster.#loadEncapsulator(encapsulateKey).encapsulate()
  }

  /**
   * Decapsulates a shared cipher key from the provided key offer.
   *
   * @param keyOffer - The encapsulated key offer artifact.
   * @param decapsulateKey - The private key agreement key.
   * @returns The reconstructed cipher key.
   */
  static async decapsulate(
    keyOffer: KeyOffer,
    decapsulateKey: DecapsulateKey
  ): Promise<{ cipherKey: CipherKey }> {
    return KeyAgreementCluster.#loadDecapsulator(decapsulateKey).decapsulate(
      keyOffer
    )
  }
}
