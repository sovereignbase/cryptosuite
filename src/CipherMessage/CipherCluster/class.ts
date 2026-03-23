import { CipherAgent } from '../CipherKeyHarness/class.js'
import type { CipherJWK } from '../index.js'

export class CipherCluster {
  static #agents = new WeakMap<CipherJWK, WeakRef<CipherAgent>>()

  static #loadAgent(cipherJwk: CipherJWK): CipherAgent {
    const weakRef = CipherCluster.#agents.get(cipherJwk)
    let agent = weakRef?.deref()
    if (!agent) {
      agent = new CipherAgent(cipherJwk)
      CipherCluster.#agents.set(cipherJwk, new WeakRef(agent))
    }
    return agent
  }

  static async encrypt(
    cipherJwk: CipherJWK,
    bytes: Uint8Array
  ): Promise<{ iv: Uint8Array; ciphertext: ArrayBuffer }> {
    const agent = CipherCluster.#loadAgent(cipherJwk)
    return await agent.encrypt(bytes)
  }

  static async decrypt(
    cipherJwk: CipherJWK,
    artifact: { iv: Uint8Array; ciphertext: ArrayBuffer }
  ): Promise<Uint8Array> {
    const agent = CipherCluster.#loadAgent(cipherJwk)
    return await agent.decrypt(artifact)
  }
}
