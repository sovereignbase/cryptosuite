import {
  CipherCluster,
  deriveCipherKey,
  generateCipherKey,
  type CipherKey,
  type CipherMessage,
} from '@sovereignbase/cryptosuite/CipherMessage'
import {
  DigitalSignatureCluster,
  deriveDigitalSignatureKeypair,
  generateDigitalSignatureKeypair,
  type SignKey,
  type VerifyKey,
} from '@sovereignbase/cryptosuite/DigitalSignature'
import {
  Identifier,
  type DeriveInput,
} from '@sovereignbase/cryptosuite/Identifier'
import {
  KeyAgreementCluster,
  deriveKeyAgreementKeypair,
  generateKeyAgreementKeypair,
  type DecapsulateKey,
  type EncapsulateKey,
  type KeyOffer,
} from '@sovereignbase/cryptosuite/KeyAgreement'
import {
  MessageAuthenticationCluster,
  deriveMessageAuthenticationKey,
  generateMessageAuthenticationKey,
  type MessageAuthenticationKey,
} from '@sovereignbase/cryptosuite/MessageAuthentication'

void CipherCluster
void deriveCipherKey
void generateCipherKey
void DigitalSignatureCluster
void deriveDigitalSignatureKeypair
void generateDigitalSignatureKeypair
void Identifier
void KeyAgreementCluster
void deriveKeyAgreementKeypair
void generateKeyAgreementKeypair
void MessageAuthenticationCluster
void deriveMessageAuthenticationKey
void generateMessageAuthenticationKey

type PublicTypes =
  | CipherKey
  | CipherMessage
  | SignKey
  | VerifyKey
  | DeriveInput
  | DecapsulateKey
  | EncapsulateKey
  | KeyOffer
  | MessageAuthenticationKey

export type { PublicTypes }
