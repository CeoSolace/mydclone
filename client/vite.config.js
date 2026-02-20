import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Vite configuration for the Discord clone client.
// The project uses React and JSX.  The server runs on port 3000 by default,
// so proxy API requests during development to avoid CORS issues.

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true
      },
      '/socket.io': {
        target: 'http://localhost:3000',
        ws: true
      }
    }
  }
});