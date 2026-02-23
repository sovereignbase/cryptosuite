import { VerifyAgent } from '../../Verifier/VerifyKeyHarness/class.js'
import { SignAgent } from '../SignAgent/class.js'
import type { SignJWK, VerifyJWK } from '../index.js'

export type VerificationAgentType = 'sign' | 'verify'
export type VerificationAgentByType = {
  sign: SignAgent
  verify: VerifyAgent
}

export class VerificationCluster {
  static #signAgents = new WeakMap<SignJWK, WeakRef<SignAgent>>()
  static #verifyAgents = new WeakMap<VerifyJWK, WeakRef<VerifyAgent>>()

  static #loadSignAgent(signJwk: SignJWK): SignAgent {
    const weakRef = VerificationCluster.#signAgents.get(signJwk)
    let agent = weakRef?.deref()
    if (!agent) {
      agent = new SignAgent(signJwk)
      VerificationCluster.#signAgents.set(signJwk, new WeakRef(agent))
    }
    return agent
  }

  static #loadVerifyAgent(verifyJwk: VerifyJWK): VerifyAgent {
    const weakRef = VerificationCluster.#verifyAgents.get(verifyJwk)
    let agent = weakRef?.deref()
    if (!agent) {
      agent = new VerifyAgent(verifyJwk)
      VerificationCluster.#verifyAgents.set(verifyJwk, new WeakRef(agent))
    }
    return agent
  }

  static async sign(signJwk: SignJWK, bytes: Uint8Array): Promise<ArrayBuffer> {
    const agent = VerificationCluster.#loadSignAgent(signJwk)
    return await agent.sign(bytes)
  }

  static async verify(
    verifyJwk: VerifyJWK,
    bytes: Uint8Array,
    signature: ArrayBuffer
  ): Promise<boolean> {
    const agent = VerificationCluster.#loadVerifyAgent(verifyJwk)
    return await agent.verify(bytes, signature)
  }
}
