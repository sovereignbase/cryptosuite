import { toUint8Array } from '@z-base/bytecodec'
import { SignKeyHarness } from './SignKeyHarness/class.js'
import { SignJWK } from './types/index.js'

export class Signer {
  static #keyHarnessCache = new WeakMap<SignJWK, WeakRef<SignKeyHarness>>()

  static #loadHarness(signJwk: SignJWK): SignKeyHarness {
    const weakRef = Signer.#keyHarnessCache.get(signJwk)
    let harness = weakRef?.deref()
    if (!harness) {
      harness = new SignKeyHarness(signJwk)
      Signer.#keyHarnessCache.set(signJwk, new WeakRef(harness))
    }
    return harness
  }

  static async sign(signJwk: SignJWK, bytes: Uint8Array): Promise<Uint8Array> {
    const harness = Signer.#loadHarness(signJwk)
    return toUint8Array(await harness.sign(bytes))
  }
}
