import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Local dev proxy: the frontend calls relative paths (/api/..., /waitlist),
// and Vite forwards them to the real Go services — kepler-web (dashboard
// JSON API) on 8444, kepler-landing (waitlist) on 8445. This means the
// same relative-path API calls work in dev and in whatever production
// serving setup eventually embeds this build (not yet decided — see
// DEPLOYMENT.md), without the frontend needing to know real hostnames.
// `secure: false` because local dev uses kepler-backend's self-signed cert.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/api': {
        target: 'https://localhost:8444',
        changeOrigin: true,
        secure: false,
      },
      '/waitlist': {
        target: 'https://localhost:8445',
        changeOrigin: true,
        secure: false,
      },
    },
  },
})
