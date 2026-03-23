import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { extname, isAbsolute, resolve, relative } from 'node:path'

const root = resolve(process.cwd())
const port = 4173

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://127.0.0.1:${port}`)
  let pathname = decodeURIComponent(url.pathname)

  if (pathname === '/') pathname = '/test/e2e/index.html'

  const filePath = resolve(root, `.${pathname}`)
  const relPath = relative(root, filePath)
  if (relPath.startsWith('..') || isAbsolute(relPath)) {
    res.statusCode = 403
    res.end('forbidden')
    return
  }

  try {
    const data = await readFile(filePath)
    const ext = extname(filePath).toLowerCase()
    res.setHeader('Content-Type', mimeTypes[ext] ?? 'application/octet-stream')
    res.statusCode = 200
    res.end(data)
  } catch {
    res.statusCode = 404
    res.end('not found')
  }
})

server.listen(port, '127.0.0.1', () => {
  console.log(`E2E server running at http://127.0.0.1:${port}`)
})
