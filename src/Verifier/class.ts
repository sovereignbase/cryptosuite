import { VerifyKeyHarness } from './VerifyKeyHarness/class.js'
import { VerifyJWK } from './types/index.js'

export class Verifier {
  static #keyHarnessCache = new WeakMap<VerifyJWK, WeakRef<VerifyKeyHarness>>()

  static #loadHarness(verifyJwk: VerifyJWK): VerifyKeyHarness {
    const weakRef = Verifier.#keyHarnessCache.get(verifyJwk)
    let harness = weakRef?.deref()
    if (!harness) {
      harness = new VerifyKeyHarness(verifyJwk)
      Verifier.#keyHarnessCache.set(verifyJwk, new WeakRef(harness))
    }
    return harness
  }

  static async verify(
    verifyJwk: VerifyJWK,
    bytes: Uint8Array,
    signature: ArrayBuffer
  ): Promise<boolean> {
    const harness = Verifier.#loadHarness(verifyJwk)
    return await harness.verify(bytes, signature)
  }
}
