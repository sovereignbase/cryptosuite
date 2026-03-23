import { HMACKeyHarness } from '../HMACKeyHarness/class.js'
import type { HMACJWK } from '../types/index.js'

export class HMACCluster {
  static #harnesses = new WeakMap<HMACJWK, WeakRef<HMACKeyHarness>>()

  static #loadHarness(hmacJwk: HMACJWK): HMACKeyHarness {
    const weakRef = HMACCluster.#harnesses.get(hmacJwk)
    let harness = weakRef?.deref()
    if (!harness) {
      harness = new HMACKeyHarness(hmacJwk)
      HMACCluster.#harnesses.set(hmacJwk, new WeakRef(harness))
    }
    return harness
  }

  static async sign(hmacJwk: HMACJWK, bytes: Uint8Array): Promise<ArrayBuffer> {
    const harness = HMACCluster.#loadHarness(hmacJwk)
    return await harness.sign(bytes)
  }

  static async verify(
    hmacJwk: HMACJWK,
    bytes: Uint8Array,
    signature: ArrayBuffer
  ): Promise<boolean> {
    const harness = HMACCluster.#loadHarness(hmacJwk)
    return await harness.verify(bytes, signature)
  }
}
