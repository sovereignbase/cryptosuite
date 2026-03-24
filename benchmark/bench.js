import { performance } from 'node:perf_hooks'
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { Cryptographic } from '../dist/index.js'

const encoder = new TextEncoder()
const fastIterationsArg = process.argv.find((arg) =>
  arg.startsWith('--iterations=')
)
const slowIterationsArg = process.argv.find((arg) =>
  arg.startsWith('--slow-iterations=')
)

const fastIterations = fastIterationsArg
  ? Number(fastIterationsArg.split('=')[1])
  : 200
const slowIterations = slowIterationsArg
  ? Number(slowIterationsArg.split('=')[1])
  : Math.max(10, Math.floor(fastIterations / 10))

function createBytes(length, offset = 0) {
  const bytes = new Uint8Array(length)
  for (let index = 0; index < length; index += 1) {
    bytes[index] = (index + offset) % 256
  }
  return bytes
}

function formatOps(durationMs, count) {
  const opsPerSec = count / (durationMs / 1000)
  return `${durationMs.toFixed(2)}ms (${opsPerSec.toFixed(1)} ops/sec)`
}

async function runBenchmark(label, count, fn) {
  await fn()

  const startedAt = performance.now()
  for (let index = 0; index < count; index += 1) {
    await fn()
  }
  const durationMs = performance.now() - startedAt

  console.log(`${label}: ${formatOps(durationMs, count)}`)
}

const identifierBytes = encoder.encode('cryptosuite benchmark identifier')
const validIdentifier = await Cryptographic.identifier.derive(identifierBytes)
const cipherDerivationSalt = createBytes(16, 17)
const cipherDerivationSource = encoder.encode(
  'cryptosuite benchmark cipher derivation source'
)
const cipherPlaintext = encoder.encode('cryptosuite benchmark cipher payload')
const messageAuthenticationSource = encoder.encode(
  'cryptosuite benchmark authentication derivation source'
)
const messageAuthenticationSalt = createBytes(16, 19)
const messageAuthenticationBytes = encoder.encode(
  'cryptosuite benchmark authentication payload'
)
const keyAgreementSeed = createBytes(ml_kem1024.lengths.seed, 29)
const digitalSignatureSeed = createBytes(ml_dsa87.lengths.seed, 43)
const digitalSignatureBytes = encoder.encode(
  'cryptosuite benchmark signature payload'
)

console.log(`Iterations: fast=${fastIterations}, slow=${slowIterations}`)

await runBenchmark('identifier.generate', fastIterations, async () => {
  await Cryptographic.identifier.generate()
})

await runBenchmark('identifier.derive', fastIterations, async () => {
  await Cryptographic.identifier.derive(identifierBytes)
})

await runBenchmark('identifier.validate', fastIterations, () => {
  if (Cryptographic.identifier.validate(validIdentifier) !== validIdentifier) {
    throw new Error('identifier.validate failed its benchmark invariant.')
  }
})

await runBenchmark('cipherMessage.generateKey', fastIterations, async () => {
  await Cryptographic.cipherMessage.generateKey()
})

await runBenchmark('cipherMessage.deriveKey', fastIterations, async () => {
  await Cryptographic.cipherMessage.deriveKey(cipherDerivationSource, {
    salt: cipherDerivationSalt,
  })
})

{
  const cipherKey = await Cryptographic.cipherMessage.generateKey()
  const cipherMessage = await Cryptographic.cipherMessage.encrypt(
    cipherKey,
    cipherPlaintext
  )

  await runBenchmark('cipherMessage.encrypt', fastIterations, async () => {
    await Cryptographic.cipherMessage.encrypt(cipherKey, cipherPlaintext)
  })

  await runBenchmark('cipherMessage.decrypt', fastIterations, async () => {
    await Cryptographic.cipherMessage.decrypt(cipherKey, cipherMessage)
  })
}

await runBenchmark(
  'messageAuthentication.generateKey',
  fastIterations,
  async () => {
    await Cryptographic.messageAuthentication.generateKey()
  }
)

await runBenchmark(
  'messageAuthentication.deriveKey',
  fastIterations,
  async () => {
    await Cryptographic.messageAuthentication.deriveKey(
      messageAuthenticationSource,
      { salt: messageAuthenticationSalt }
    )
  }
)

{
  const messageAuthenticationKey =
    await Cryptographic.messageAuthentication.generateKey()
  const authenticationSignature =
    await Cryptographic.messageAuthentication.sign(
      messageAuthenticationKey,
      messageAuthenticationBytes
    )

  await runBenchmark('messageAuthentication.sign', fastIterations, async () => {
    await Cryptographic.messageAuthentication.sign(
      messageAuthenticationKey,
      messageAuthenticationBytes
    )
  })

  await runBenchmark(
    'messageAuthentication.verify',
    fastIterations,
    async () => {
      const verified = await Cryptographic.messageAuthentication.verify(
        messageAuthenticationKey,
        messageAuthenticationBytes,
        authenticationSignature
      )
      if (verified !== true) {
        throw new Error(
          'messageAuthentication.verify failed its benchmark invariant.'
        )
      }
    }
  )
}

await runBenchmark('keyAgreement.generateKeypair', slowIterations, async () => {
  await Cryptographic.keyAgreement.generateKeypair()
})

await runBenchmark('keyAgreement.deriveKeypair', slowIterations, async () => {
  await Cryptographic.keyAgreement.deriveKeypair(keyAgreementSeed)
})

{
  const { encapsulateKey, decapsulateKey } =
    await Cryptographic.keyAgreement.generateKeypair()
  const { keyOffer } =
    await Cryptographic.keyAgreement.encapsulate(encapsulateKey)

  await runBenchmark('keyAgreement.encapsulate', slowIterations, async () => {
    await Cryptographic.keyAgreement.encapsulate(encapsulateKey)
  })

  await runBenchmark('keyAgreement.decapsulate', slowIterations, async () => {
    await Cryptographic.keyAgreement.decapsulate(keyOffer, decapsulateKey)
  })
}

await runBenchmark(
  'digitalSignature.generateKeypair',
  slowIterations,
  async () => {
    await Cryptographic.digitalSignature.generateKeypair()
  }
)

await runBenchmark(
  'digitalSignature.deriveKeypair',
  slowIterations,
  async () => {
    await Cryptographic.digitalSignature.deriveKeypair(digitalSignatureSeed)
  }
)

{
  const { signKey, verifyKey } =
    await Cryptographic.digitalSignature.generateKeypair()
  const signature = await Cryptographic.digitalSignature.sign(
    signKey,
    digitalSignatureBytes
  )

  await runBenchmark('digitalSignature.sign', slowIterations, async () => {
    await Cryptographic.digitalSignature.sign(signKey, digitalSignatureBytes)
  })

  await runBenchmark('digitalSignature.verify', slowIterations, async () => {
    const verified = await Cryptographic.digitalSignature.verify(
      verifyKey,
      digitalSignatureBytes,
      signature
    )
    if (verified !== true) {
      throw new Error('digitalSignature.verify failed its benchmark invariant.')
    }
  })
}
