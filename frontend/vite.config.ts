import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// /api isteklerini backend'e yönlendir. Tarayıcı açısından her şey aynı adresten geldiği için
// backend'de CORS açmamıza gerek kalmaz (açık CORS = gereksiz saldırı yüzeyi).
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    proxy: {
      '/api': 'http://127.0.0.1:8000',
    },
  },
})
