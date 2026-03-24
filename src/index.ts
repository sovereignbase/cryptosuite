/*
Copyright 2026 z-base

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
/***/
import { deriveOID, generateOID, validateOID } from './Identifier/index.js'
/***/
import {
  CipherCluster,
  deriveCipherKey,
  generateCipherKey,
} from './CipherMessage/index.js'
/***/
import {
  MessageAuthenticationCluster,
  deriveMessageAuthenticationKey,
  generateMessageAuthenticationKey,
} from './MessageAuthentication/index.js'
/***/
import {
  KeyAgreementCluster,
  deriveKeyAgreementKeypair,
  generateKeyAgreementKeypair,
} from './KeyAgreement/index.js'
/***/
import {
  DigitalSignatureCluster,
  deriveDigitalSignatureKeypair,
  generateDigitalSignatureKeypair,
} from './DigitalSignature/index.js'
/***/

/**
 * Exposes the public cryptographic API surface of this package.
 */
export class Cryptographic {
  /**
   * Opaque identifier operations.
   */
  static readonly identifier = {
    /** See {@link deriveOID}. */
    derive: deriveOID,
    /** See {@link generateOID}. */
    generate: generateOID,
    /** See {@link validateOID}. */
    validate: validateOID,
  }
  /**
   * Symmetric cipher operations.
   */
  static readonly cipherMessage = {
    /** See {@link CipherCluster.encrypt}. */
    encrypt: CipherCluster.encrypt,
    /** See {@link CipherCluster.decrypt}. */
    decrypt: CipherCluster.decrypt,
    /** See {@link deriveCipherKey}. */
    deriveKey: deriveCipherKey,
    /** See {@link generateCipherKey}. */
    generateKey: generateCipherKey,
  }
  /**
   * Symmetric message authentication operations.
   */
  static readonly messageAuthentication = {
    /** See {@link MessageAuthenticationCluster.sign}. */
    sign: MessageAuthenticationCluster.sign,
    /** See {@link MessageAuthenticationCluster.verify}. */
    verify: MessageAuthenticationCluster.verify,
    /** See {@link deriveMessageAuthenticationKey}. */
    deriveKey: deriveMessageAuthenticationKey,
    /** See {@link generateMessageAuthenticationKey}. */
    generateKey: generateMessageAuthenticationKey,
  }
  /**
   * Key agreement operations.
   */
  static readonly keyAgreement = {
    /** See {@link KeyAgreementCluster.encapsulate}. */
    encapsulate: KeyAgreementCluster.encapsulate,
    /** See {@link KeyAgreementCluster.decapsulate}. */
    decapsulate: KeyAgreementCluster.decapsulate,
    /** See {@link deriveKeyAgreementKeypair}. */
    deriveKeypair: deriveKeyAgreementKeypair,
    /** See {@link generateKeyAgreementKeypair}. */
    generateKeypair: generateKeyAgreementKeypair,
  }
  /**
   * Digital signature operations.
   */
  static readonly digitalSignature = {
    /** See {@link DigitalSignatureCluster.sign}. */
    sign: DigitalSignatureCluster.sign,
    /** See {@link DigitalSignatureCluster.verify}. */
    verify: DigitalSignatureCluster.verify,
    /** See {@link deriveDigitalSignatureKeypair}. */
    deriveKeypair: deriveDigitalSignatureKeypair,
    /** See {@link generateDigitalSignatureKeypair}. */
    generateKeypair: generateDigitalSignatureKeypair,
  }
}
