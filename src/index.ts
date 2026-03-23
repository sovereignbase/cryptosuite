/***/
import {
  CipherCluster,
  deriveCipherKey,
  generateCipherKey,
} from './Cipher/index.js'
/***/
import {
  KeyAgreementCluster,
  generateKeyAgreementKeypair,
} from './KeyEncapsulation/index.js'
/***/
import {
  deriveHMACKey,
  generateHMACKey,
  HMACCluster,
} from './MessageAuthentication/index.js'
/***/
import { deriveOID, generateOID, validateOID } from './Identifiers/index.js'
/***/
import {
  DigitalSignatureCluster,
  generateDigitalSignatureKeypair,
} from './DigitalSignatures/index.js'
/***/
export class Cryptosuite {
  /***/
  static readonly identifiers = {
    derive: deriveOID,
    generate: generateOID,
    validate: validateOID,
  }
  /***/
  static readonly cipher = {
    encrypt: CipherCluster.encrypt,
    decrypt: CipherCluster.decrypt,
    deriveKey: deriveCipherKey,
    generateKey: generateCipherKey,
  }
  static readonly messageAuthentication = {
    sign: HMACCluster.sign,
    verify: HMACCluster.verify,
    deriveKey: deriveHMACKey,
    generateKey: generateHMACKey,
  }
  /***/
  static readonly keyAgreement = {
    encapsulate: KeyAgreementCluster.wrap,
    decapsulate: KeyAgreementCluster.unwrap,
    generateKeypair: generateKeyAgreementKeypair,
  }
  static readonly digitalSignatures = {
    sign: DigitalSignatureCluster.sign,
    verify: DigitalSignatureCluster.verify,
    generateKeypair: generateDigitalSignatureKeypair,
  }
  /***/
}
