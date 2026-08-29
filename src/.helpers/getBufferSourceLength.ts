import { CryptosuiteError } from '../.errors/class.js'

export function getBufferSourceLength(
  source: Uint8Array | ArrayBuffer,
  context = 'value'
): number {
  if (source instanceof ArrayBuffer) return source.byteLength
  if (source instanceof Uint8Array) return source.byteLength

  throw new CryptosuiteError(
    'BUFFER_SOURCE_EXPECTED',
    `${context}: expected a Uint8Array or ArrayBuffer.`
  )
}
