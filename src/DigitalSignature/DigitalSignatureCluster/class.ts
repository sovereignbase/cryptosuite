/*
Copyright 2026 Sovereignbase

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import { SignKeyHarness } from '../.core/SignKeyHarness/class.js'
import type { SignKey, VerifyKey } from '../.core/types/index.js'
import { VerifyKeyHarness } from '../.core/VerifyKeyHarness/class.js'

/**
 * Routes digital signature operations through cached key harness instances.
 */
export class DigitalSignatureCluster {
  static #signers = new WeakMap<SignKey, WeakRef<SignKeyHarness>>()
  static #verifiers = new WeakMap<VerifyKey, WeakRef<VerifyKeyHarness>>()

  static #loadSigner(signKey: SignKey): SignKeyHarness {
    const weakRef = DigitalSignatureCluster.#signers.get(signKey)
    let harness = weakRef?.deref()
    if (!harness) {
      harness = new SignKeyHarness(signKey)
      DigitalSignatureCluster.#signers.set(signKey, new WeakRef(harness))
    }
    return harness
  }

  static #loadVerifier(verifyKey: VerifyKey): VerifyKeyHarness {
    const weakRef = DigitalSignatureCluster.#verifiers.get(verifyKey)
    let harness = weakRef?.deref()
    if (!harness) {
      harness = new VerifyKeyHarness(verifyKey)
      DigitalSignatureCluster.#verifiers.set(verifyKey, new WeakRef(harness))
    }
    return harness
  }

  /**
   * Signs message bytes with the provided private signature key.
   *
   * @param signKey - The private signature key to use.
   * @param bytes - The message bytes to sign.
   * @returns The generated signature bytes.
   */
  static async sign(signKey: SignKey, bytes: Uint8Array): Promise<Uint8Array> {
    return await DigitalSignatureCluster.#loadSigner(signKey).sign(bytes)
  }

  /**
   * Verifies signature bytes against the provided message bytes.
   *
   * @param verifyKey - The public signature verification key.
   * @param bytes - The signed message bytes.
   * @param signature - The signature bytes to verify.
   * @returns `true` when the signature is valid; otherwise `false`.
   */
  static async verify(
    verifyKey: VerifyKey,
    bytes: Uint8Array,
    signature: Uint8Array
  ): Promise<boolean> {
    return await DigitalSignatureCluster.#loadVerifier(verifyKey).verify(
      bytes,
      signature
    )
  }
}
