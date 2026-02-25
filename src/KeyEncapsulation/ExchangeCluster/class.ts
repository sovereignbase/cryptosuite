import { WrapAgent } from '../WrapAgent/class.js'
import { UnwrapAgent } from '../UnwrapAgent/class.js'
import type { UnwrapJWK, WrapJWK } from '../index.js'
import type { CipherJWK } from '../../Cipher/index.js'

export type ExchangeAgentType = 'wrap' | 'unwrap'
export type ExchangeAgentByType = {
  wrap: WrapAgent
  unwrap: UnwrapAgent
}

export class ExchangeCluster {
  static #wrapAgents = new WeakMap<WrapJWK, WeakRef<WrapAgent>>()
  static #unwrapAgents = new WeakMap<UnwrapJWK, WeakRef<UnwrapAgent>>()

  static #loadWrapAgent(wrapJwk: WrapJWK): WrapAgent {
    const weakRef = ExchangeCluster.#wrapAgents.get(wrapJwk)
    let agent = weakRef?.deref()
    if (!agent) {
      agent = new WrapAgent(wrapJwk)
      ExchangeCluster.#wrapAgents.set(wrapJwk, new WeakRef(agent))
    }
    return agent
  }

  static #loadUnwrapAgent(unwrapJwk: UnwrapJWK): UnwrapAgent {
    const weakRef = ExchangeCluster.#unwrapAgents.get(unwrapJwk)
    let agent = weakRef?.deref()
    if (!agent) {
      agent = new UnwrapAgent(unwrapJwk)
      ExchangeCluster.#unwrapAgents.set(unwrapJwk, new WeakRef(agent))
    }
    return agent
  }

  static async wrap(
    wrapJwk: WrapJWK,
    cipherJwk: CipherJWK
  ): Promise<ArrayBuffer> {
    const agent = ExchangeCluster.#loadWrapAgent(wrapJwk)
    return await agent.wrap(cipherJwk)
  }

  static async unwrap(
    unwrapJwk: UnwrapJWK,
    wrapped: ArrayBuffer
  ): Promise<CipherJWK> {
    const agent = ExchangeCluster.#loadUnwrapAgent(unwrapJwk)
    return await agent.unwrap(wrapped)
  }
}
