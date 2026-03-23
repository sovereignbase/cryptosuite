import { CipherKeyHarness } from '../CipherKeyHarness/class.js'
import type { CipherJWK, CipherMessageArtifact } from '../index.js'

export class CipherCluster {
  static #harnesses = new WeakMap<CipherJWK, WeakRef<CipherKeyHarness>>()

  static #loadHarness(cipherJwk: CipherJWK): CipherKeyHarness {
    const weakRef = CipherCluster.#harnesses.get(cipherJwk)
    let harness = weakRef?.deref()
    if (!harness) {
      harness = new CipherKeyHarness(cipherJwk)
      CipherCluster.#harnesses.set(cipherJwk, new WeakRef(harness))
    }
    return harness
  }

  static async encrypt(
    cipherJwk: CipherJWK,
    bytes: Uint8Array
  ): Promise<CipherMessageArtifact> {
    const harness = CipherCluster.#loadHarness(cipherJwk)
    return await harness.encrypt(bytes)
  }

  static async decrypt(
    cipherJwk: CipherJWK,
    artifact: CipherMessageArtifact
  ): Promise<Uint8Array> {
    const harness = CipherCluster.#loadHarness(cipherJwk)
    return await harness.decrypt(artifact)
  }
}
