import { Bytes, type ByteSource } from '@sovereignbase/bytecodec'
import {
  CryptosuiteError,
  type CryptosuiteErrorCode,
} from '../.errors/class.js'

export function normalizeBytes(
  source: unknown,
  context = 'value',
  code: CryptosuiteErrorCode = 'BUFFER_SOURCE_EXPECTED'
): Uint8Array<ArrayBuffer> {
  try {
    return new Uint8Array(Bytes.normalize(source as ByteSource))
  } catch {
    throw new CryptosuiteError(
      code,
      `${context}: expected byte-compatible input.`
    )
  }
}
