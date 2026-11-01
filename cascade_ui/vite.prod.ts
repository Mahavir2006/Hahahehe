// Production-only build plugins: a Content-Security-Policy and pre-compressed (gzip + Brotli) assets.
import fs from "node:fs"
import path from "node:path"
import zlib from "node:zlib"
import type { Plugin } from "vite"

/** Strict CSP as a <meta> tag on the built page: only our own scripts, styles, fonts and API calls. */
export function contentSecurityPolicy(): Plugin {
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'", // React sets inline style attributes (risk-bar widths, colours)
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ")
  return {
    name: "cascadeshield-csp",
    apply: "build", // the dev server needs inline HMR scripts, so CSP is only added to builds
    transformIndexHtml: () => [{ tag: "meta", attrs: { "http-equiv": "Content-Security-Policy", content: csp }, injectTo: "head-prepend" }],
  }
}

/** Write .gz and .br next to every text asset so a static server can send them directly. */
export function precompress(): Plugin {
  let outDir = "dist"
  return {
    name: "cascadeshield-precompress",
    apply: "build",
    configResolved: (c) => void (outDir = path.resolve(c.root, c.build.outDir)),
    closeBundle() {
      const walk = (dir: string): string[] => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]))
      for (const file of walk(outDir).filter((f) => /\.(js|css|html|svg|json)$/.test(f))) {
        const buf = fs.readFileSync(file)
        if (buf.length < 1024) continue
        fs.writeFileSync(file + ".gz", zlib.gzipSync(buf, { level: 9 }))
        fs.writeFileSync(file + ".br", zlib.brotliCompressSync(buf, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 11 } }))
      }
    },
  }
}
