import { MessageAuthenticationKeyHarness } from '../.core/MessageAuthenticationKeyHarness/class.js'
import type { MessageAuthenticationKey } from '../.core/types/index.js'

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

  static async sign(
    messageAuthenticationKey: MessageAuthenticationKey,
    bytes: Uint8Array
  ): Promise<ArrayBuffer> {
    const harness = MessageAuthenticationCluster.#loadHarness(
      messageAuthenticationKey
    )
    return await harness.sign(bytes)
  }

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
