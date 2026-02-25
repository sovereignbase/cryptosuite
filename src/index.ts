/***/
import {
  CipherCluster,
  deriveCipherKey,
  generateCipherKey,
} from './Cipher/index.js'
/***/
import {
  ExchangeCluster,
  generateExchangePair,
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
  Signer,
  type SignJWK,
  Verifier,
  type VerifyJWK,
  generateDigitalSignaturesPair,
} from './DigitalSignatures/index.js'
/***/
export {
  generateCipherKey,
  deriveCipherKey,
  CipherAgent,
  CipherCluster,
  type CipherJWK,
} from './Cipher/index.js'
/***/
export {
  generateExchangePair,
  WrapAgent,
  UnwrapAgent,
  ExchangeCluster,
  type WrapJWK,
  type UnwrapJWK,
} from './KeyEncapsulation/index.js'
/***/
export {
  generateHMACKey,
  deriveHMACKey,
  HMACAgent,
  HMACCluster,
  type HMACJWK,
} from './MessageAuthentication/index.js'
/***/
export {
  deriveOID,
  generateOID,
  validateOID,
  type OpaqueIdentifier,
} from './Identifiers/index.js'
/***/
export {
  Signer,
  type SignJWK,
  Verifier,
  type VerifyJWK,
  generateDigitalSignaturesPair,
} from './DigitalSignatures/index.js'

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
  static readonly keyEncapsulation = {
    wrap: ExchangeCluster.wrap,
    unwrap: ExchangeCluster.unwrap,
    generatePair: generateExchangePair,
  }
  static readonly digitalSignatures = {
    sign: Signer.sign,
    verify: Verifier.verify,
    generatePair: generateDigitalSignaturesPair,
  }
  /***/
}
