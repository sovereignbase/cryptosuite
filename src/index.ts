/***/
import { deriveOID, generateOID, validateOID } from './Identifiers/index.js'
/***/
import {
  CipherCluster,
  deriveCipherKey,
  generateCipherKey,
} from './CipherMessage/index.js'
/***/
import {
  HMACCluster,
  deriveHMACKey,
  generateHMACKey,
} from './MessageAuthentication/index.js'
/***/
import {
  KeyAgreementCluster,
  generateKeyAgreementKeypair,
} from './KeyAgreement/index.js'
/***/
import {
  DigitalSignatureCluster,
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
    sign: HMACCluster.sign,
    verify: HMACCluster.verify,
    deriveKey: deriveHMACKey,
    generateKey: generateHMACKey,
  },
  /***/
  keyAgreement: {
    encapsulate: KeyAgreementCluster.encapsulate,
    decapsulate: KeyAgreementCluster.decapsulate,
    generateKeypair: generateKeyAgreementKeypair,
  },
  /***/
  digitalSignature: {
    sign: DigitalSignatureCluster.sign,
    verify: DigitalSignatureCluster.verify,
    generateKeypair: generateDigitalSignatureKeypair,
  },
}
