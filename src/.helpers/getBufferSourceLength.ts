/*
Copyright 2026 z-base

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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
