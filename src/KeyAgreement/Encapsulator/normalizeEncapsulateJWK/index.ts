import { CryptosuiteError } from '../../../.errors/class.js'
import { resolveKeyAgreementAlgorithm } from '../../resolveKeyAgreementAlgorithm/index.js'
import type { EncapsulateJWK } from '../types/index.js'

export function normalizeEncapsulateJWK(jwk: JsonWebKey): EncapsulateJWK {
  const candidate = jwk as JsonWebKey | null

  if (!candidate || typeof candidate !== 'object') {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID',
      'normalizeEncapsulateJWK: expected an asymmetric public key agreement JWK.'
    )
  }

  if (
    typeof candidate.kty !== 'string' ||
    typeof candidate.alg !== 'string' ||
    'd' in candidate ||
    'p' in candidate ||
    'q' in candidate ||
    'dp' in candidate ||
    'dq' in candidate ||
    'qi' in candidate ||
    'oth' in candidate ||
    'k' in candidate
  ) {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID',
      'normalizeEncapsulateJWK: expected an asymmetric public key agreement JWK.'
    )
  }

  if (candidate.use !== undefined && candidate.use !== 'enc') {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID',
      'normalizeEncapsulateJWK: JWK.use must be "enc" when present.'
    )
  }

  const strategy = resolveKeyAgreementAlgorithm(candidate)
  if (candidate.key_ops !== undefined) {
    if (!Array.isArray(candidate.key_ops)) {
      throw new CryptosuiteError(
        'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID',
        'normalizeEncapsulateJWK: JWK.key_ops must be an array when present.'
      )
    }

    if (strategy.mode === 'wrap') {
      if (candidate.key_ops.length !== 1 || candidate.key_ops[0] !== 'wrapKey') {
        throw new CryptosuiteError(
          'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID',
          'normalizeEncapsulateJWK: RSA encapsulation JWK.key_ops must be ["wrapKey"] when present.'
        )
      }
    } else if (candidate.key_ops.length !== 0) {
      throw new CryptosuiteError(
        'KEY_AGREEMENT_ENCAPSULATE_JWK_INVALID',
        'normalizeEncapsulateJWK: derived key agreement public JWK.key_ops must be [] when present.'
      )
    }
  }

  return {
    ...jwk,
    use: 'enc',
    key_ops: strategy.mode === 'wrap' ? (['wrapKey'] as const) : ([] as const),
  } as EncapsulateJWK
}
