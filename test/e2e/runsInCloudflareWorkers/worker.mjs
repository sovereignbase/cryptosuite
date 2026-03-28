import { Cryptographic } from '../../../dist/index.js'
import { runCryptosuiteRuntimeSuite } from '../runtime-suite.mjs'

export default {
  async fetch(request) {
    if (new URL(request.url).pathname !== '/')
      return new Response('Not found', { status: 404 })

    try {
      const results = await runCryptosuiteRuntimeSuite(Cryptographic)
      return Response.json(results)
    } catch (error) {
      const message =
        error instanceof Error ? (error.stack ?? error.message) : String(error)

      return new Response(message, { status: 500 })
    }
  },
}
