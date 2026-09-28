import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// /api isteklerini backend'e yönlendir. Tarayıcı açısından her şey aynı adresten geldiği için
// backend'de CORS açmamıza gerek kalmaz (açık CORS = gereksiz saldırı yüzeyi).
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    proxy: {
      // SIEM_API_PORT: aynı anda ikinci bir kopya (ör. test veritabanıyla) çalıştırmak için
      '/api': `http://127.0.0.1:${process.env.SIEM_API_PORT ?? '8000'}`,
    },
  },
})
