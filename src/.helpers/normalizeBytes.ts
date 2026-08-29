import { toUint8Array, type ByteSource } from '@sovereignbase/bytecodec'
import {
  CryptosuiteError,
  type CryptosuiteErrorCode,
} from '../.errors/class.js'

export function normalizeBytes(
  source: unknown,
  context = 'value',
  code: CryptosuiteErrorCode = 'BUFFER_SOURCE_EXPECTED'
): Uint8Array {
  try {
    return toUint8Array(source as ByteSource)
  } catch {
    throw new CryptosuiteError(
      code,
      `${context}: expected byte-compatible input.`
    )
  }
}
