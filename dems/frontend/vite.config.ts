import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath, URL } from 'node:url'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Optional local HTTPS (recommended: `mkcert localhost`). Drop the two files into ./certs and the
// dev server switches to https://localhost:5173 automatically.
const certFile = fileURLToPath(new URL('./certs/localhost.pem', import.meta.url))
const keyFile = fileURLToPath(new URL('./certs/localhost-key.pem', import.meta.url))
const https = existsSync(certFile) && existsSync(keyFile)
  ? { cert: readFileSync(certFile), key: readFileSync(keyFile) }
  : undefined

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    host: 'localhost',
    port: 5173,
    strictPort: true, // the backend's CORS allow-list is locked to this origin
    https,
    proxy: {
      // Browser calls /api/cases -> FastAPI receives /cases (same-origin, so no CORS pre-flight)
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: false,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
  build: { sourcemap: false, target: 'es2022' },
})
