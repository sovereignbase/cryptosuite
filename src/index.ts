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
    /** Encrypts plaintext bytes with a symmetric cipher key. */
    encrypt: CipherCluster.encrypt,
    /** Decrypts a cipher message into plaintext bytes. */
    decrypt: CipherCluster.decrypt,
    /** Derives a symmetric cipher key from source key material. */
    deriveKey: deriveCipherKey,
    /** Generates a symmetric cipher key. */
    generateKey: generateCipherKey,
  }
  /**
   * Symmetric message authentication operations.
   */
  static readonly messageAuthentication = {
    /** Produces an authentication tag for message bytes. */
    sign: MessageAuthenticationCluster.sign,
    /** Verifies an authentication tag for message bytes. */
    verify: MessageAuthenticationCluster.verify,
    /** Derives a message authentication key from source key material. */
    deriveKey: deriveMessageAuthenticationKey,
    /** Generates a message authentication key. */
    generateKey: generateMessageAuthenticationKey,
  }
  /**
   * Key agreement operations.
   */
  static readonly keyAgreement = {
    /** Encapsulates a shared cipher key for a recipient. */
    encapsulate: KeyAgreementCluster.encapsulate,
    /** Decapsulates a shared cipher key from a key offer. */
    decapsulate: KeyAgreementCluster.decapsulate,
    /** Derives a key agreement key pair from source key material. */
    deriveKeypair: deriveKeyAgreementKeypair,
    /** Generates a key agreement key pair. */
    generateKeypair: generateKeyAgreementKeypair,
  }
  /**
   * Digital signature operations.
   */
  static readonly digitalSignature = {
    /** Signs message bytes with a private signature key. */
    sign: DigitalSignatureCluster.sign,
    /** Verifies signature bytes with a public verification key. */
    verify: DigitalSignatureCluster.verify,
    /** Derives a digital signature key pair from source key material. */
    deriveKeypair: deriveDigitalSignatureKeypair,
    /** Generates a digital signature key pair. */
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
