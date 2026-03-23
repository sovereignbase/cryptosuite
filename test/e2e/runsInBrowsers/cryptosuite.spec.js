import { test, expect } from '@playwright/test'

async function evaluate(page, fn) {
  return page.evaluate(fn)
}

test('AES-GCM encrypt/decrypt roundtrip or correct error', async ({ page }) => {
  await page.goto('/')
  const result = await evaluate(page, async () => {
    const { generateCipherKey, CipherAgent } = await import('/dist/index.js')
    const plaintext = new Uint8Array([1, 2, 3])
    try {
      const key = await generateCipherKey()
      const agent = new CipherAgent(key)
      const enc = await agent.encrypt(plaintext)
      const dec = await agent.decrypt(enc)
      return { ok: true, bytes: Array.from(dec) }
    } catch (err) {
      return { ok: false, name: err?.name, code: err?.code }
    }
  })

  if (!result.ok) {
    expect(result.code).toBe('AES_GCM_UNSUPPORTED')
  } else {
    expect(result.bytes).toEqual([1, 2, 3])
  }
})

test('HMAC sign/verify roundtrip or correct error', async ({ page }) => {
  await page.goto('/')
  const result = await evaluate(page, async () => {
    const { generateHMACKey, HMACAgent } = await import('/dist/index.js')
    const payload = new Uint8Array([4, 5, 6])
    try {
      const key = await generateHMACKey()
      const agent = new HMACAgent(key)
      const sig = await agent.sign(payload)
      const ok = await agent.verify(payload, sig)
      return { ok: true, verified: ok }
    } catch (err) {
      return { ok: false, name: err?.name, code: err?.code }
    }
  })

  if (!result.ok) {
    expect(result.code).toBe('HMAC_SHA256_UNSUPPORTED')
  } else {
    expect(result.verified).toBe(true)
  }
})

test('Ed25519 sign/verify or correct error', async ({ page }) => {
  await page.goto('/')
  const result = await evaluate(page, async () => {
    const { generateVerificationPair, SignAgent, VerifyAgent } =
      await import('/dist/index.js')
    const payload = new Uint8Array([7, 8, 9])
    try {
      const { signJwk, verifyJwk } = await generateVerificationPair()
      const signer = new SignAgent(signJwk)
      const verifier = new VerifyAgent(verifyJwk)
      const sig = await signer.sign(payload)
      const ok = await verifier.verify(payload, sig)
      return { ok: true, verified: ok }
    } catch (err) {
      return { ok: false, name: err?.name, code: err?.code }
    }
  })

  if (!result.ok) {
    expect(['ED25519_UNSUPPORTED', 'ED25519_ALG_INVALID']).toContain(
      result.code
    )
  } else {
    expect(result.verified).toBe(true)
  }
})

test('RSA wrap/unwrap or correct error', async ({ page }) => {
  test.setTimeout(60000)
  await page.goto('/')
  const result = await evaluate(page, async () => {
    const { generateExchangePair, generateCipherKey, WrapAgent, UnwrapAgent } =
      await import('/dist/index.js')
    try {
      const { wrapJwk, unwrapJwk } = await generateExchangePair()
      const cipherJwk = await generateCipherKey()
      const wrapper = new WrapAgent(wrapJwk)
      const unwrapper = new UnwrapAgent(unwrapJwk)
      const wrapped = await wrapper.wrap(cipherJwk)
      const unwrapped = await unwrapper.unwrap(wrapped)
      return { ok: true, kty: unwrapped.kty }
    } catch (err) {
      return { ok: false, name: err?.name, code: err?.code }
    }
  })

  if (!result.ok) {
    expect(result.code).toBe('RSA_OAEP_UNSUPPORTED')
  } else {
    expect(result.kty).toBe('oct')
  }
})

test('OID generate/derive/validate', async ({ page }) => {
  await page.goto('/')
  const result = await evaluate(page, async () => {
    const { generateOID, deriveOID, validateOID } =
      await import('/dist/index.js')
    const data = new Uint8Array([1, 1, 2, 2, 3, 3])
    try {
      const id = await generateOID()
      const derived = await deriveOID(data)
      const valid = validateOID(id)
      const derivedValid = validateOID(derived)
      const invalid = validateOID('not-valid')
      return {
        ok: true,
        valid: valid !== false,
        derivedValid: derivedValid !== false,
        invalid: invalid === false,
      }
    } catch (err) {
      return { ok: false, name: err?.name, code: err?.code }
    }
  })

  if (!result.ok) {
    expect(result.code).toBe('SHA256_UNSUPPORTED')
  } else {
    expect(result.valid).toBe(true)
    expect(result.derivedValid).toBe(true)
    expect(result.invalid).toBe(true)
  }
})
