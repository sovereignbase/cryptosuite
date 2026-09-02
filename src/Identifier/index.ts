import { Bytes, type ByteSource } from '@sovereignbase/bytecodec'
import { isRecord } from '@sovereignbase/utils'

/** Input accepted by {@link Identifier.derive}. */
export type DeriveInput =
  | ByteSource
  | {
      /** String value to decode before derivation. */
      value: string
      /** String encoding. Defaults to `utf8`. */
      encoding?: 'utf8' | 'base64' | 'base64url'
    }

/** Generates, derives, and validates canonical base64url identifiers. */
export class Identifier {
  /**
   * Generates a cryptographically random identifier.
   *
   * @param byteLength - Number of random bytes represented by the identifier.
   * @returns A canonical, unpadded base64url identifier.
   */
  static generate(byteLength: number): string {
    return Bytes.base64url.encode(Bytes.generate(byteLength))
  }

  /**
   * Derives a deterministic, domain-separated identifier.
   *
   * String inputs default to UTF-8 and can explicitly select base64 or
   * base64url decoding. The same inputs and byte length produce the same
   * identifier.
   *
   * @param base - Base value used as the derivation salt.
   * @param domain - Context identifying the identifier's purpose.
   * @param byteLength - Number of derived bytes represented by the identifier.
   * @returns A canonical, unpadded base64url identifier.
   */
  static async derive(
    base: DeriveInput,
    domain: DeriveInput,
    byteLength: number
  ): Promise<string> {
    const baseBytes = isRecord(base)
      ? Bytes[base.encoding ?? 'utf8'].decode(base.value)
      : base
    const domainBytes = isRecord(domain)
      ? Bytes[domain.encoding ?? 'utf8'].decode(domain.value)
      : domain

    return Bytes.base64url.encode(
      await Bytes.derive(baseBytes, domainBytes, byteLength)
    )
  }

  /**
   * Checks the canonical base64url representation and decoded byte length.
   *
   * @param value - Candidate identifier.
   * @param byteLength - Required decoded byte length.
   * @returns Whether the value is a canonical identifier of the required size.
   */
  static validate(value: unknown, byteLength: number): value is string {
    try {
      if (typeof value !== 'string') throw null
      const buffer = Bytes.base64url.decode(value)
      return (
        buffer.byteLength === byteLength &&
        Bytes.base64url.encode(buffer) === value
      )
    } catch {
      return false
    }
  }
}
