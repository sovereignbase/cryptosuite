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
  deriveKeyAgreementKeyPair,
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
    /** See {@link deriveKeyAgreementKeyPair}. */
    deriveKeyPair: deriveKeyAgreementKeyPair,
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
