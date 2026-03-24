import { MessageAuthenticationKeyHarness } from '../.core/MessageAuthenticationKeyHarness/class.js'
import type { MessageAuthenticationKey } from '../.core/types/index.js'

/**
 * Routes message authentication operations through cached key harness instances.
 */
export class MessageAuthenticationCluster {
  static #harnesses = new WeakMap<
    MessageAuthenticationKey,
    WeakRef<MessageAuthenticationKeyHarness>
  >()

  static #loadHarness(
    messageAuthenticationKey: MessageAuthenticationKey
  ): MessageAuthenticationKeyHarness {
    const weakRef = MessageAuthenticationCluster.#harnesses.get(
      messageAuthenticationKey
    )
    let harness = weakRef?.deref()
    if (!harness) {
      harness = new MessageAuthenticationKeyHarness(messageAuthenticationKey)
      MessageAuthenticationCluster.#harnesses.set(
        messageAuthenticationKey,
        new WeakRef(harness)
      )
    }
    return harness
  }

  /**
   * Produces a message authentication tag for the provided bytes.
   *
   * @param messageAuthenticationKey - The symmetric authentication key to use.
   * @param bytes - The message bytes to authenticate.
   * @returns The computed authentication tag.
   */
  static async sign(
    messageAuthenticationKey: MessageAuthenticationKey,
    bytes: Uint8Array
  ): Promise<ArrayBuffer> {
    const harness = MessageAuthenticationCluster.#loadHarness(
      messageAuthenticationKey
    )
    return await harness.sign(bytes)
  }

  /**
   * Verifies a message authentication tag for the provided bytes.
   *
   * @param messageAuthenticationKey - The symmetric authentication key to use.
   * @param bytes - The message bytes to verify.
   * @param signature - The authentication tag to verify.
   * @returns `true` when the tag is valid; otherwise `false`.
   */
  static async verify(
    messageAuthenticationKey: MessageAuthenticationKey,
    bytes: Uint8Array,
    signature: ArrayBuffer
  ): Promise<boolean> {
    const harness = MessageAuthenticationCluster.#loadHarness(
      messageAuthenticationKey
    )
    return await harness.verify(bytes, signature)
  }
}
