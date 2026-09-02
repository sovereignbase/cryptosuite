function now() {
  return globalThis.performance?.now?.() ?? Date.now()
}

function fail(message) {
  throw new Error(message)
}

function assert(condition, message) {
  if (!condition) fail(message)
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    fail(`${message}: expected ${String(expected)}, got ${String(actual)}`)
  }
}

function assertBytesEqual(actual, expected, message) {
  assert(actual instanceof Uint8Array, `${message}: expected Uint8Array output`)
  assert(
    actual.byteLength === expected.byteLength,
    `${message}: byte length mismatch`
  )

  for (let index = 0; index < actual.byteLength; index += 1) {
    if (actual[index] !== expected[index]) {
      fail(`${message}: mismatch at index ${index}`)
    }
  }
}

function serializeError(error) {
  return {
    name: error?.name ?? 'Error',
    code: error?.code,
    message: error?.message ?? String(error),
  }
}

export async function runCryptosuiteRuntimeSuite(Cryptographic) {
  const startedAt = now()
  const results = []
  const plaintext = new TextEncoder().encode('cryptosuite runtime')
  const cipherSalt = new Uint8Array(16).fill(9)
  const messageAuthenticationSalt = new Uint8Array(16).fill(7)
  const keyAgreementSeed = Uint8Array.from({ length: 32 }, (_, index) => {
    return (index + 11) % 256
  })
  const digitalSignatureSeed = Uint8Array.from({ length: 64 }, (_, index) => {
    return (index + 17) % 256
  })

  async function run(name, fn) {
    const testStartedAt = now()
    try {
      await fn()
      results.push({
        name,
        ok: true,
        durationMs: Number((now() - testStartedAt).toFixed(4)),
      })
    } catch (error) {
      results.push({
        name,
        ok: false,
        durationMs: Number((now() - testStartedAt).toFixed(4)),
        error: serializeError(error),
      })
    }
  }

  await run('static API is wired', async () => {
    assert(
      typeof Cryptographic.identifier.generate === 'function',
      'identifier.generate is missing'
    )
    assert(
      typeof Cryptographic.identifier.derive === 'function',
      'identifier.derive is missing'
    )
    assert(
      typeof Cryptographic.identifier.validate === 'function',
      'identifier.validate is missing'
    )
    assert(
      typeof Cryptographic.cipherMessage.generateKey === 'function',
      'cipherMessage.generateKey is missing'
    )
    assert(
      typeof Cryptographic.cipherMessage.deriveKey === 'function',
      'cipherMessage.deriveKey is missing'
    )
    assert(
      typeof Cryptographic.cipherMessage.encrypt === 'function',
      'cipherMessage.encrypt is missing'
    )
    assert(
      typeof Cryptographic.cipherMessage.decrypt === 'function',
      'cipherMessage.decrypt is missing'
    )
    assert(
      typeof Cryptographic.messageAuthentication.generateKey === 'function',
      'messageAuthentication.generateKey is missing'
    )
    assert(
      typeof Cryptographic.messageAuthentication.deriveKey === 'function',
      'messageAuthentication.deriveKey is missing'
    )
    assert(
      typeof Cryptographic.messageAuthentication.sign === 'function',
      'messageAuthentication.sign is missing'
    )
    assert(
      typeof Cryptographic.messageAuthentication.verify === 'function',
      'messageAuthentication.verify is missing'
    )
    assert(
      typeof Cryptographic.keyAgreement.generateKeypair === 'function',
      'keyAgreement.generateKeypair is missing'
    )
    assert(
      typeof Cryptographic.keyAgreement.deriveKeypair === 'function',
      'keyAgreement.deriveKeypair is missing'
    )
    assert(
      typeof Cryptographic.keyAgreement.encapsulate === 'function',
      'keyAgreement.encapsulate is missing'
    )
    assert(
      typeof Cryptographic.keyAgreement.decapsulate === 'function',
      'keyAgreement.decapsulate is missing'
    )
    assert(
      typeof Cryptographic.digitalSignature.generateKeypair === 'function',
      'digitalSignature.generateKeypair is missing'
    )
    assert(
      typeof Cryptographic.digitalSignature.deriveKeypair === 'function',
      'digitalSignature.deriveKeypair is missing'
    )
    assert(
      typeof Cryptographic.digitalSignature.sign === 'function',
      'digitalSignature.sign is missing'
    )
    assert(
      typeof Cryptographic.digitalSignature.verify === 'function',
      'digitalSignature.verify is missing'
    )
  })

  await run('identifier.generate returns a valid identifier', async () => {
    const identifier = Cryptographic.identifier.generate(24)

    assertEqual(identifier.length, 32, 'identifier length mismatch')
    assert(
      Cryptographic.identifier.validate(identifier, 24),
      'generated identifier must validate'
    )
  })

  await run(
    'identifier.derive is deterministic and domain-separated',
    async () => {
      const first = await Cryptographic.identifier.derive(
        { value: 'runtime-base' },
        { value: 'runtime-domain' },
        24
      )
      const second = await Cryptographic.identifier.derive(
        { value: 'runtime-base' },
        { value: 'runtime-domain' },
        24
      )
      const separateDomain = await Cryptographic.identifier.derive(
        { value: 'runtime-base' },
        { value: 'other-domain' },
        24
      )

      assertEqual(first, second, 'derived identifiers must match')
      assert(first !== separateDomain, 'domains must separate identifiers')
    }
  )

  await run('identifier.validate rejects malformed identifiers', async () => {
    assert(
      !Cryptographic.identifier.validate('not an identifier', 24),
      'malformed identifier must not validate'
    )
  })

  await run('cipherMessage.generateKey returns an AES-GCM key', async () => {
    const cipherKey = await Cryptographic.cipherMessage.generateKey()
    assertEqual(cipherKey.kty, 'oct', 'cipher key must be symmetric')
    assertEqual(cipherKey.alg, 'A256GCM', 'cipher key alg must be A256GCM')
    assert(typeof cipherKey.k === 'string', 'cipher key material must exist')
  })

  await run('cipherMessage.deriveKey accepts an optional salt', async () => {
    const one = await Cryptographic.cipherMessage.deriveKey(
      plaintext,
      cipherSalt
    )
    const two = await Cryptographic.cipherMessage.deriveKey(
      plaintext,
      cipherSalt
    )
    assertEqual(one.k, two.k, 'derived cipher keys must match')
    assertEqual(one.alg, 'A256GCM', 'derived cipher key alg mismatch')
  })

  await run('cipherMessage.encrypt returns a cipher artifact', async () => {
    const cipherKey = await Cryptographic.cipherMessage.generateKey()
    const cipherMessage = await Cryptographic.cipherMessage.encrypt(
      cipherKey,
      plaintext
    )

    assert(cipherMessage.iv.byteLength === 12, 'cipher iv must be 12 bytes')
    assert(
      cipherMessage.ciphertext instanceof Uint8Array,
      'ciphertext must be a Uint8Array'
    )
  })

  await run('cipherMessage.decrypt restores plaintext', async () => {
    const cipherKey = await Cryptographic.cipherMessage.generateKey()
    const cipherMessage = await Cryptographic.cipherMessage.encrypt(
      cipherKey,
      plaintext
    )
    const decrypted = await Cryptographic.cipherMessage.decrypt(
      cipherKey,
      cipherMessage
    )
    assertBytesEqual(decrypted, plaintext, 'cipher roundtrip failed')
  })

  await run(
    'messageAuthentication.generateKey returns an HS256 key',
    async () => {
      const key = await Cryptographic.messageAuthentication.generateKey()
      assertEqual(key.kty, 'oct', 'message authentication key must be oct')
      assertEqual(key.alg, 'HS256', 'message authentication key must be HS256')
      assert(typeof key.k === 'string', 'message authentication key must exist')
    }
  )

  await run(
    'messageAuthentication.deriveKey accepts an optional salt',
    async () => {
      const one = await Cryptographic.messageAuthentication.deriveKey(
        plaintext,
        messageAuthenticationSalt
      )
      const two = await Cryptographic.messageAuthentication.deriveKey(
        plaintext,
        messageAuthenticationSalt
      )
      assertEqual(
        one.k,
        two.k,
        'message authentication derivation must be deterministic'
      )
      assertEqual(
        one.alg,
        'HS256',
        'derived message authentication key alg mismatch'
      )
    }
  )

  await run('messageAuthentication.sign returns a tag', async () => {
    const key = await Cryptographic.messageAuthentication.generateKey()
    const signature = await Cryptographic.messageAuthentication.sign(
      key,
      plaintext
    )
    assert(signature instanceof Uint8Array, 'tag must be a Uint8Array')
    assert(
      signature.byteLength > 0,
      'message authentication tag must not be empty'
    )
  })

  await run(
    'messageAuthentication.verify accepts valid tags and rejects tampering',
    async () => {
      const key = await Cryptographic.messageAuthentication.generateKey()
      const signature = await Cryptographic.messageAuthentication.sign(
        key,
        plaintext
      )
      const verified = await Cryptographic.messageAuthentication.verify(
        key,
        plaintext,
        signature
      )
      const rejected = await Cryptographic.messageAuthentication.verify(
        key,
        new Uint8Array([0, ...plaintext]),
        signature
      )

      assert(verified === true, 'message authentication verification failed')
      assert(rejected === false, 'tampered message should not verify')
    }
  )

  await run(
    'keyAgreement.generateKeypair returns X25519-ML-KEM-768 keys',
    async () => {
      const { encapsulateKey, decapsulateKey } =
        await Cryptographic.keyAgreement.generateKeypair()
      assertEqual(encapsulateKey.kty, 'AKP', 'encapsulate key must be AKP')
      assertEqual(
        encapsulateKey.alg,
        'X25519-ML-KEM-768',
        'encapsulate key alg mismatch'
      )
      assert(
        typeof encapsulateKey.x === 'string',
        'encapsulate key x must exist'
      )
      assertEqual(decapsulateKey.kty, 'AKP', 'decapsulate key must be AKP')
      assertEqual(
        decapsulateKey.alg,
        'X25519-ML-KEM-768',
        'decapsulate key alg mismatch'
      )
      assert(
        typeof decapsulateKey.d === 'string',
        'decapsulate key d must exist'
      )
    }
  )

  await run('keyAgreement.deriveKeypair is deterministic', async () => {
    const one = await Cryptographic.keyAgreement.deriveKeypair(keyAgreementSeed)
    const two = await Cryptographic.keyAgreement.deriveKeypair(keyAgreementSeed)
    assertEqual(
      one.encapsulateKey.x,
      two.encapsulateKey.x,
      'encapsulate keys must match'
    )
    assertEqual(
      one.decapsulateKey.d,
      two.decapsulateKey.d,
      'decapsulate keys must match'
    )
  })

  await run(
    'keyAgreement.encapsulate returns a key offer and cipher key',
    async () => {
      const { encapsulateKey } =
        await Cryptographic.keyAgreement.generateKeypair()
      const { keyOffer, cipherKey } =
        await Cryptographic.keyAgreement.encapsulate(encapsulateKey)
      assert(
        keyOffer.ciphertext instanceof Uint8Array,
        'key offer ciphertext must be a Uint8Array'
      )
      assertEqual(
        cipherKey.alg,
        'A256GCM',
        'encapsulated cipher key alg mismatch'
      )
    }
  )

  await run(
    'keyAgreement.decapsulate reconstructs the shared cipher key',
    async () => {
      const { encapsulateKey, decapsulateKey } =
        await Cryptographic.keyAgreement.generateKeypair()
      const { keyOffer, cipherKey: localCipherKey } =
        await Cryptographic.keyAgreement.encapsulate(encapsulateKey)
      const { cipherKey: remoteCipherKey } =
        await Cryptographic.keyAgreement.decapsulate(keyOffer, decapsulateKey)

      assertEqual(
        localCipherKey.k,
        remoteCipherKey.k,
        'encapsulated and decapsulated cipher keys differ'
      )

      const cipherMessage = await Cryptographic.cipherMessage.encrypt(
        localCipherKey,
        plaintext
      )
      const decrypted = await Cryptographic.cipherMessage.decrypt(
        remoteCipherKey,
        cipherMessage
      )
      assertBytesEqual(
        decrypted,
        plaintext,
        'agreed cipher key roundtrip failed'
      )
    }
  )

  await run(
    'digitalSignature.generateKeypair returns Ed25519-ML-DSA-65 keys',
    async () => {
      const { signKey, verifyKey } =
        await Cryptographic.digitalSignature.generateKeypair()
      assertEqual(signKey.kty, 'AKP', 'sign key must be AKP')
      assertEqual(signKey.alg, 'Ed25519-ML-DSA-65', 'sign key alg mismatch')
      assert(typeof signKey.d === 'string', 'sign key d must exist')
      assertEqual(verifyKey.kty, 'AKP', 'verify key must be AKP')
      assertEqual(verifyKey.alg, 'Ed25519-ML-DSA-65', 'verify key alg mismatch')
      assert(typeof verifyKey.x === 'string', 'verify key x must exist')
    }
  )

  await run('digitalSignature.deriveKeypair is deterministic', async () => {
    const one =
      await Cryptographic.digitalSignature.deriveKeypair(digitalSignatureSeed)
    const two =
      await Cryptographic.digitalSignature.deriveKeypair(digitalSignatureSeed)
    assertEqual(one.signKey.d, two.signKey.d, 'sign keys must match')
    assertEqual(one.verifyKey.x, two.verifyKey.x, 'verify keys must match')
  })

  await run('digitalSignature.sign returns a signature', async () => {
    const { signKey } = await Cryptographic.digitalSignature.generateKeypair()
    const signature = await Cryptographic.digitalSignature.sign(
      signKey,
      plaintext
    )
    assert(signature.byteLength > 0, 'signature must not be empty')
  })

  await run(
    'digitalSignature.verify accepts valid signatures and rejects tampering',
    async () => {
      const { signKey, verifyKey } =
        await Cryptographic.digitalSignature.generateKeypair()
      const signature = await Cryptographic.digitalSignature.sign(
        signKey,
        plaintext
      )
      const verified = await Cryptographic.digitalSignature.verify(
        verifyKey,
        plaintext,
        signature
      )
      const rejected = await Cryptographic.digitalSignature.verify(
        verifyKey,
        new Uint8Array([255, ...plaintext]),
        signature
      )

      assert(verified === true, 'digital signature verification failed')
      assert(rejected === false, 'tampered message should not verify')
    }
  )

  return {
    results,
    total: results.length,
    passed: results.filter((result) => result.ok).length,
    failed: results.filter((result) => !result.ok).length,
    durationMs: Number((now() - startedAt).toFixed(4)),
  }
}

export function formatRuntimeSummary(label, summary) {
  const lines = [`${label}: ${summary.passed}/${summary.total} passed`]

  for (const result of summary.results) {
    if (!result.ok) {
      const detail = result.error.code ?? result.error.message
      lines.push(`  - ${result.name}: ${detail}`)
    }
  }

  return lines.join('\n')
}

export function assertRuntimeSummary(label, summary) {
  if (summary.failed > 0) {
    throw new Error(formatRuntimeSummary(label, summary))
  }
}
