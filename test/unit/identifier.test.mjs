import assert from 'node:assert/strict'
import { test } from 'vitest'
import { Identifier as BuiltIdentifier } from '../../dist/Identifier/index.js'
import { Identifier as SourceIdentifier } from '../../src/Identifier/index.ts'

for (const [surface, Identifier] of [
  ['source', SourceIdentifier],
  ['build', BuiltIdentifier],
]) {
  test(`${surface} Identifier.generate returns a canonical identifier of the requested byte length`, () => {
    const identifier = Identifier.generate(32)

    assert.equal(identifier.length, 43)
    assert.equal(Identifier.validate(identifier, 32), true)
  })

  test(`${surface} Identifier.derive is deterministic and domain-separated for byte inputs`, async () => {
    const base = new Uint8Array([1, 2, 3, 4])
    const first = await Identifier.derive(base, [5, 6, 7], 24)
    const second = await Identifier.derive(base, [5, 6, 7], 24)
    const separateDomain = await Identifier.derive(base, [5, 6, 8], 24)

    assert.equal(first, second)
    assert.notEqual(first, separateDomain)
    assert.equal(Identifier.validate(first, 24), true)
  })

  test(`${surface} Identifier.derive decodes string inputs using the selected encoding`, async () => {
    const raw = await Identifier.derive(
      new TextEncoder().encode('base'),
      new TextEncoder().encode('domain'),
      16
    )
    const utf8 = await Identifier.derive(
      { value: 'base' },
      { value: 'domain' },
      16
    )
    const encoded = await Identifier.derive(
      { value: 'YmFzZQ==', encoding: 'base64' },
      { value: 'ZG9tYWlu', encoding: 'base64url' },
      16
    )

    assert.equal(utf8, raw)
    assert.equal(encoded, raw)
  })

  test(`${surface} Identifier.validate rejects non-canonical values and incorrect lengths`, () => {
    assert.equal(Identifier.validate('AAA', 2), true)
    assert.equal(Identifier.validate('AAA', 3), false)
    assert.equal(Identifier.validate('AAB', 2), false)
    assert.equal(Identifier.validate('AAA=', 2), false)
    assert.equal(Identifier.validate('AAA!', 2), false)
    assert.equal(Identifier.validate('A', 0), false)
    assert.equal(Identifier.validate(123, 2), false)
  })
}
