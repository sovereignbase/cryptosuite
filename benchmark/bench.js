import { performance } from 'node:perf_hooks'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  combineSigners,
  ecSigner,
  ml_kem768_x25519,
} from '@noble/post-quantum/hybrid.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { Cryptographic } from '../dist/index.js'

const encoder = new TextEncoder()
const iterationsArg = process.argv.find((arg) =>
  arg.startsWith('--iterations=')
)
const iterations = iterationsArg ? Number(iterationsArg.split('=')[1]) : 100

if (!Number.isInteger(iterations) || iterations <= 0) {
  throw new Error('benchmark iterations must be a positive integer.')
}

const ed25519MlDsa65 = combineSigners(
  undefined,
  (seed) => seed,
  ecSigner(ed25519),
  ml_dsa65
)

function createBytes(length, offset = 0) {
  const bytes = new Uint8Array(length)
  for (let index = 0; index < length; index += 1) {
    bytes[index] = (index + offset) % 256
  }
  return bytes
}

function formatNumber(value, fractionDigits) {
  return value.toFixed(fractionDigits)
}

async function measure(label, ops, fn) {
  await fn()

  const startedAt = performance.now()
  for (let index = 0; index < ops; index += 1) {
    await fn()
  }
  const durationMs = performance.now() - startedAt

  return {
    label,
    ops,
    ms: durationMs,
    msPerOp: durationMs / ops,
    opsPerSec: ops / (durationMs / 1000),
  }
}

function printTable(results) {
  console.log(`Iterations: ${iterations}`)
  console.log('')
  console.log('| Benchmark | ops | ms | ms/op | ops/sec |')
  console.log('| --- | ---: | ---: | ---: | ---: |')

  for (const result of results) {
    console.log(
      `| \`${result.label}\` | ${result.ops} | ${formatNumber(result.ms, 2)} | ${formatNumber(result.msPerOp, 4)} | ${formatNumber(result.opsPerSec, 2)} |`
    )
  }
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
const keyAgreementSeed = createBytes(ml_kem768_x25519.lengths.seed, 29)
const digitalSignatureSeed = createBytes(ed25519MlDsa65.lengths.seed, 43)
const digitalSignatureBytes = encoder.encode(
  'cryptosuite benchmark signature payload'
)

const results = []

results.push(
  await measure('identifier.generate', iterations, async () => {
    await Cryptographic.identifier.generate()
  })
)

results.push(
  await measure('identifier.derive', iterations, async () => {
    await Cryptographic.identifier.derive(identifierBytes)
  })
)

results.push(
  await measure('identifier.validate', iterations, () => {
    if (
      Cryptographic.identifier.validate(validIdentifier) !== validIdentifier
    ) {
      throw new Error('identifier.validate failed its benchmark invariant.')
    }
  })
)

results.push(
  await measure('cipherMessage.generateKey', iterations, async () => {
    await Cryptographic.cipherMessage.generateKey()
  })
)

results.push(
  await measure('cipherMessage.deriveKey', iterations, async () => {
    await Cryptographic.cipherMessage.deriveKey(cipherDerivationSource, {
      salt: cipherDerivationSalt,
    })
  })
)

{
  const cipherKey = await Cryptographic.cipherMessage.generateKey()
  const cipherMessage = await Cryptographic.cipherMessage.encrypt(
    cipherKey,
    cipherPlaintext
  )

  results.push(
    await measure('cipherMessage.encrypt', iterations, async () => {
      await Cryptographic.cipherMessage.encrypt(cipherKey, cipherPlaintext)
    })
  )

  results.push(
    await measure('cipherMessage.decrypt', iterations, async () => {
      await Cryptographic.cipherMessage.decrypt(cipherKey, cipherMessage)
    })
  )
}

results.push(
  await measure('messageAuthentication.generateKey', iterations, async () => {
    await Cryptographic.messageAuthentication.generateKey()
  })
)

results.push(
  await measure('messageAuthentication.deriveKey', iterations, async () => {
    await Cryptographic.messageAuthentication.deriveKey(
      messageAuthenticationSource,
      { salt: messageAuthenticationSalt }
    )
  })
)

{
  const messageAuthenticationKey =
    await Cryptographic.messageAuthentication.generateKey()
  const authenticationSignature =
    await Cryptographic.messageAuthentication.sign(
      messageAuthenticationKey,
      messageAuthenticationBytes
    )

  results.push(
    await measure('messageAuthentication.sign', iterations, async () => {
      await Cryptographic.messageAuthentication.sign(
        messageAuthenticationKey,
        messageAuthenticationBytes
      )
    })
  )

  results.push(
    await measure('messageAuthentication.verify', iterations, async () => {
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
    })
  )
}

results.push(
  await measure('keyAgreement.generateKeypair', iterations, async () => {
    await Cryptographic.keyAgreement.generateKeypair()
  })
)

results.push(
  await measure('keyAgreement.deriveKeypair', iterations, async () => {
    await Cryptographic.keyAgreement.deriveKeypair(keyAgreementSeed)
  })
)

{
  const { encapsulateKey, decapsulateKey } =
    await Cryptographic.keyAgreement.generateKeypair()
  const { keyOffer } =
    await Cryptographic.keyAgreement.encapsulate(encapsulateKey)

  results.push(
    await measure('keyAgreement.encapsulate', iterations, async () => {
      await Cryptographic.keyAgreement.encapsulate(encapsulateKey)
    })
  )

  results.push(
    await measure('keyAgreement.decapsulate', iterations, async () => {
      await Cryptographic.keyAgreement.decapsulate(keyOffer, decapsulateKey)
    })
  )
}

results.push(
  await measure('digitalSignature.generateKeypair', iterations, async () => {
    await Cryptographic.digitalSignature.generateKeypair()
  })
)

results.push(
  await measure('digitalSignature.deriveKeypair', iterations, async () => {
    await Cryptographic.digitalSignature.deriveKeypair(digitalSignatureSeed)
  })
)

{
  const { signKey, verifyKey } =
    await Cryptographic.digitalSignature.generateKeypair()
  const signature = await Cryptographic.digitalSignature.sign(
    signKey,
    digitalSignatureBytes
  )

  results.push(
    await measure('digitalSignature.sign', iterations, async () => {
      await Cryptographic.digitalSignature.sign(signKey, digitalSignatureBytes)
    })
  )

  results.push(
    await measure('digitalSignature.verify', iterations, async () => {
      const verified = await Cryptographic.digitalSignature.verify(
        verifyKey,
        digitalSignatureBytes,
        signature
      )
      if (verified !== true) {
        throw new Error(
          'digitalSignature.verify failed its benchmark invariant.'
        )
      }
    })
  )
}

printTable(results)
