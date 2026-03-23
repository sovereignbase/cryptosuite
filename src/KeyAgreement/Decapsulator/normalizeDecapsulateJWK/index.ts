import { CryptosuiteError } from '../../../.errors/class.js'
import { resolveKeyAgreementAlgorithm } from '../../resolveKeyAgreementAlgorithm/index.js'
import type { DecapsulateJWK } from '../types/index.js'

export function normalizeDecapsulateJWK(jwk: JsonWebKey): DecapsulateJWK {
  const candidate = jwk as JsonWebKey | null

  if (!candidate || typeof candidate !== 'object') {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_DECAPSULATE_JWK_INVALID',
      'normalizeDecapsulateJWK: expected an asymmetric private key agreement JWK.'
    )
  }

  if (
    typeof candidate.kty !== 'string' ||
    typeof candidate.alg !== 'string' ||
    typeof candidate.d !== 'string' ||
    'k' in candidate
  ) {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_DECAPSULATE_JWK_INVALID',
      'normalizeDecapsulateJWK: expected an asymmetric private key agreement JWK.'
    )
  }

  if (candidate.use !== undefined && candidate.use !== 'enc') {
    throw new CryptosuiteError(
      'KEY_AGREEMENT_DECAPSULATE_JWK_INVALID',
      'normalizeDecapsulateJWK: JWK.use must be "enc" when present.'
    )
  }

  const strategy = resolveKeyAgreementAlgorithm(candidate)
  if (candidate.key_ops !== undefined) {
    if (!Array.isArray(candidate.key_ops)) {
      throw new CryptosuiteError(
        'KEY_AGREEMENT_DECAPSULATE_JWK_INVALID',
        'normalizeDecapsulateJWK: JWK.key_ops must be an array when present.'
      )
    }

    if (strategy.mode === 'wrap') {
      if (candidate.key_ops.length !== 1 || candidate.key_ops[0] !== 'unwrapKey') {
        throw new CryptosuiteError(
          'KEY_AGREEMENT_DECAPSULATE_JWK_INVALID',
          'normalizeDecapsulateJWK: RSA decapsulation JWK.key_ops must be ["unwrapKey"] when present.'
        )
      }
    } else {
      const ops = new Set(candidate.key_ops)
      if (
        ops.size === 0 ||
        [...ops].some((op) => op !== 'deriveKey' && op !== 'deriveBits')
      ) {
        throw new CryptosuiteError(
          'KEY_AGREEMENT_DECAPSULATE_JWK_INVALID',
          'normalizeDecapsulateJWK: derived key agreement private JWK.key_ops must contain only deriveKey/deriveBits.'
        )
      }
    }
  }

  return {
    ...jwk,
    use: 'enc',
    key_ops:
      strategy.mode === 'wrap'
        ? (['unwrapKey'] as const)
        : (['deriveKey', 'deriveBits'] as const),
  } as DecapsulateJWK
}
