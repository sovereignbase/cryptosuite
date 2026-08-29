import { CipherKeyHarness } from '../.core/CipherKeyHarness/class.js'
import type { CipherKey, CipherMessage } from '../.core/types/index.js'

/**
 * Routes cipher operations through cached key harness instances.
 */
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

  /**
   * Encrypts message bytes with the provided cipher key.
   *
   * @param cipherKey - The symmetric cipher key to use.
   * @param messageBytes - The plaintext bytes to encrypt.
   * @returns The cipher message artifact.
   */
  static async encrypt(
    cipherKey: CipherKey,
    messageBytes: Uint8Array
  ): Promise<CipherMessage> {
    const harness = CipherCluster.#loadHarness(cipherKey)
    return await harness.encrypt(messageBytes)
  }

  /**
   * Decrypts a cipher message with the provided cipher key.
   *
   * @param cipherKey - The symmetric cipher key to use.
   * @param cipherMessage - The cipher message artifact to decrypt.
   * @returns The decrypted plaintext bytes.
   */
  static async decrypt(
    cipherKey: CipherKey,
    cipherMessage: CipherMessage
  ): Promise<Uint8Array> {
    const harness = CipherCluster.#loadHarness(cipherKey)
    return await harness.decrypt(cipherMessage)
  }
}
