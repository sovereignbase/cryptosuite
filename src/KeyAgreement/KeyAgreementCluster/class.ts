import { EncapsulateJWKHarness } from '../Encapsulator/EncapsulateJWKHarness/class.js'
import { UnwrapAgent } from '../Unwrapper/UnwrapAgent/class.js'
import { generateCipherKey, type CipherJWK } from '../../Cipher/index.js'
import type { EncapsulateJWK } from '../Encapsulator/types/index.js'
import type { DecapsulateJWK } from '../Decapsulator/types/index.js'

export type ExchangeAgentType = 'encapsulate' | 'decapsulate'
export type ExchangeAgentByType = {
  wrap: EncapsulateJWKHarness
  unwrap: UnwrapAgent
}

export class KeyAgreementCluster {
  static #wrapAgents = new WeakMap<EncapsulateJWK, WeakRef<WrapAgent>>()
  static #unwrapAgents = new WeakMap<DecapsulateJWK, WeakRef<UnwrapAgent>>()

  static #loadWrapAgent(wrapJwk: WrapJWK): WrapAgent {
    const weakRef = KeyAgreementCluster.#wrapAgents.get(wrapJwk)
    let agent = weakRef?.deref()
    if (!agent) {
      agent = new WrapAgent(wrapJwk)
      KeyAgreementCluster.#wrapAgents.set(wrapJwk, new WeakRef(agent))
    }
    return agent
  }

  static #loadUnwrapAgent(unwrapJwk: UnwrapJWK): UnwrapAgent {
    const weakRef = KeyAgreementCluster.#unwrapAgents.get(unwrapJwk)
    let agent = weakRef?.deref()
    if (!agent) {
      agent = new UnwrapAgent(unwrapJwk)
      KeyAgreementCluster.#unwrapAgents.set(unwrapJwk, new WeakRef(agent))
    }
    return agent
  }

  static async encapsulate(
    encapsulateJwk: EncapsulateJWK
  ): Promise<{ ciphertext: ArrayBuffer; sharedCipherJwk: CipherJWK }> {
    const sharedCipherJwk = await generateCipherKey()
    const harness = KeyAgreementCluster.#loadWrapAgent(encapsulateJwk)
    const ciphertext = await harness.encapsulate(sharedCipherJwk)
    return { ciphertext, sharedCipherJwk }
  }

  static async decapsulate(
    ciphertext: ArrayBuffer,
    decapsulateJwk: DecapsulateJWK
  ): Promise<{ sharedCipherJwk: CipherJWK }> {
    const agent = KeyAgreementCluster.#loadUnwrapAgent(decapsulateJwk)
    const sharedCipherJwk = await agent.decapsulate(ciphertext)
    return { sharedCipherJwk }
  }
}
