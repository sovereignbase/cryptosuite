/**
 * Runtime-agnostic public API for the Sovereignbase cryptography toolkit.
 *
 * The package exposes symmetric encryption, message authentication, key
 * agreement, and digital signatures through a declarative static API surface.
 */
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

export type { CipherKey, CipherMessage } from './CipherMessage/index.js'
export type { MessageAuthenticationKey } from './MessageAuthentication/index.js'
export type {
  EncapsulateKey,
  DecapsulateKey,
  KeyOffer,
} from './KeyAgreement/index.js'
export type { SignKey, VerifyKey } from './DigitalSignature/index.js'
export type { CryptosuiteError, CryptosuiteErrorCode } from './.errors/class.js'
