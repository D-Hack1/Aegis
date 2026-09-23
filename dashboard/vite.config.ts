import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const targetUrl = env.VITE_API_URL || 'http://localhost:8000';

  return {
    plugins: [react()],
    server: {
      proxy: {
        '/alerts': {
          target: targetUrl,
          changeOrigin: true,
        },
        '/stats': {
          target: targetUrl,
          changeOrigin: true,
        },
        '/kill-chains': {
          target: targetUrl,
          changeOrigin: true,
        },
        '/metrics': {
          target: targetUrl,
          changeOrigin: true,
        },
        '/health': {
          target: targetUrl,
          changeOrigin: true,
        },
        '/demo': {
          target: targetUrl,
          changeOrigin: true,
        }
      }
    }
  }
})
