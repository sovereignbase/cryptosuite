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

export const cryptographic = {
  /***/
  identifier: {
    derive: deriveOID,
    generate: generateOID,
    validate: validateOID,
  },
  /***/
  cipherMessage: {
    encrypt: CipherCluster.encrypt,
    decrypt: CipherCluster.decrypt,
    deriveKey: deriveCipherKey,
    generateKey: generateCipherKey,
  },
  /***/
  messageAuthentication: {
    sign: MessageAuthenticationCluster.sign,
    verify: MessageAuthenticationCluster.verify,
    deriveKey: deriveMessageAuthenticationKey,
    generateKey: generateMessageAuthenticationKey,
  },
  /***/
  keyAgreement: {
    encapsulate: KeyAgreementCluster.encapsulate,
    decapsulate: KeyAgreementCluster.decapsulate,
    deriveKeyPair: deriveKeyAgreementKeyPair,
    generateKeypair: generateKeyAgreementKeypair,
  },
  /***/
  digitalSignature: {
    sign: DigitalSignatureCluster.sign,
    verify: DigitalSignatureCluster.verify,
    deriveKeypair: deriveDigitalSignatureKeypair,
    generateKeypair: generateDigitalSignatureKeypair,
  },
}
