import { generateKeyAgreementKeypair } from './generateKeyAgreementKeypair/index.js'

export { generateKeyAgreementKeypair } from './generateKeyAgreementKeypair/index.js'
export { EncapsulateJWKHarness } from './Encapsulator/EncapsulateKeyHarness/class.js'
export { DecapsulateJWKHarness } from './Decapsulator/DecapuslateKeyHarness/class.js'
export { KeyAgreementCluster } from './KeyAgreementCluster/class.js'
export type { EncapsulateJWK } from './Encapsulator/types/index.js'
export type { DecapsulateJWK } from './Decapsulator/types/index.js'
export type {
  KeyAgreementArtifact,
  SharedKeyContext,
  SharedKeyJWK,
} from './types/index.js'

export { EncapsulateJWKHarness as WrapAgent } from './Encapsulator/EncapsulateKeyHarness/class.js'
export { DecapsulateJWKHarness as UnwrapAgent } from './Decapsulator/DecapuslateKeyHarness/class.js'
export { KeyAgreementCluster as ExchangeCluster } from './KeyAgreementCluster/class.js'
export type { EncapsulateJWK as WrapJWK } from './Encapsulator/types/index.js'
export type { DecapsulateJWK as UnwrapJWK } from './Decapsulator/types/index.js'

export async function generateExchangePair() {
  const { encapsulateJwk, decapsulateJwk } = await generateKeyAgreementKeypair({
    name: 'RSA-OAEP',
    modulusLength: 4096,
    hash: 'SHA-256',
  })

  return {
    wrapJwk: encapsulateJwk,
    unwrapJwk: decapsulateJwk,
  }
}
