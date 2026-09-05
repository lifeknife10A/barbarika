import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// https://vite.dev/config/
// Sentry backend for the dev proxy. Point at a dev-insecure (plaintext) Sentry;
// override with SENTRY_ORIGIN when it runs elsewhere.
const SENTRY_ORIGIN = process.env.SENTRY_ORIGIN || 'http://127.0.0.1:8000'
// Krishna-owned compliance service (fills the official CERT-In form from the vault).
const COMPLIANCE_ORIGIN = process.env.COMPLIANCE_ORIGIN || 'http://127.0.0.1:8100'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: false,
    host: '0.0.0.0',
    // Same-origin bridge. /api/compliance/* → the compliance service (more
    // specific, must be declared first); everything else /api/* → Sentry.
    proxy: {
      '/api/compliance': {
        target: COMPLIANCE_ORIGIN,
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api\/compliance/, ''),
      },
      '/api': {
        target: SENTRY_ORIGIN,
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ''),
      },
    },
  },
})
