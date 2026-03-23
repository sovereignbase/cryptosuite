import { CipherKeyHarness } from '../.core/CipherKeyHarness/class.js'
import type { CipherKey, CipherMessage } from '../.core/types/index.js'

export class CipherCluster {
  static #harnesses = new WeakMap<CipherKey, WeakRef<CipherKeyHarness>>()

  static #loadHarness(cipherKey: CipherKey): CipherKeyHarness {
    const weakRef = CipherCluster.#harnesses.get(cipherKey)
    let harness = weakRef?.deref()
    if (!harness) {
      harness = new CipherKeyHarness(cipherKey)
      CipherCluster.#harnesses.set(cipherKey, new WeakRef(harness))
    }
    return harness
  }

  static async encrypt(
    cipherKey: CipherKey,
    messageBytes: Uint8Array
  ): Promise<CipherMessage> {
    const harness = CipherCluster.#loadHarness(cipherKey)
    return await harness.encrypt(messageBytes)
  }

  static async decrypt(
    cipherKey: CipherKey,
    cipherMessage: CipherMessage
  ): Promise<Uint8Array> {
    const harness = CipherCluster.#loadHarness(cipherKey)
    return await harness.decrypt(cipherMessage)
  }
}
