import assert from 'node:assert/strict'

const ORIGINAL_CRYPTO = globalThis.crypto

export function setCrypto(value) {
  Object.defineProperty(globalThis, 'crypto', {
    value,
    configurable: true,
    writable: true,
  })
}

export function restoreCrypto() {
  if (ORIGINAL_CRYPTO === undefined) {
    delete globalThis.crypto
    return
  }

  setCrypto(ORIGINAL_CRYPTO)
}

export function buildCrypto(overrides = {}) {
  const subtleOverrides = overrides.subtle ?? {}
  const hasGetRandomValues = Object.prototype.hasOwnProperty.call(
    overrides,
    'getRandomValues'
  )

  return {
    getRandomValues: hasGetRandomValues
      ? overrides.getRandomValues
      : (array) => array,
    subtle: {
      digest: async () => new Uint8Array(48).buffer,
      generateKey: async () => ({}),
      importKey: async () => ({}),
      deriveKey: async () => ({}),
      exportKey: async () => ({}),
      encrypt: async () => new Uint8Array([1, 2, 3]).buffer,
      decrypt: async () => new Uint8Array([1, 2, 3]).buffer,
      sign: async () => new Uint8Array([4, 5, 6]).buffer,
      verify: async () => true,
      ...subtleOverrides,
    },
  }
}

export function expectErrorLike(error, code) {
  assert.equal(error?.name, 'CryptosuiteError')
  assert.equal(error?.code, code)
  assert.equal(typeof error?.message, 'string')
  assert.equal(error.message.startsWith('{@sovereignbase/cryptosuite} '), true)
}

export function expectCodeSync(fn, code) {
  try {
    fn()
    assert.fail(`Expected ${code}`)
  } catch (error) {
    expectErrorLike(error, code)
    return error
  }
}

export async function expectCodeAsync(fn, code) {
  try {
    await fn()
    assert.fail(`Expected ${code}`)
  } catch (error) {
    expectErrorLike(error, code)
    return error
  }
}
