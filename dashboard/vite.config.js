import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// https://vite.dev/config/
// Sentry backend for the dev proxy. Point at a dev-insecure (plaintext) Sentry;
// override with SENTRY_ORIGIN when it runs elsewhere.
const SENTRY_ORIGIN = process.env.SENTRY_ORIGIN || 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: false,
    host: '0.0.0.0',
    // Same-origin bridge: browser calls /api/* → Sentry. Avoids CORS and keeps
    // the browser off mTLS (Sentry terminates TLS itself in production).
    proxy: {
      '/api': {
        target: SENTRY_ORIGIN,
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ''),
      },
    },
  },
})
