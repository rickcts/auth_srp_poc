import path from "path"
import tailwindcss from "@tailwindcss/vite"
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

const polyfills = () => nodePolyfills({
  include: ['buffer', 'process', 'crypto', 'stream', 'util'], 
  globals: {
    Buffer: true,
    global: true,
    process: true,
  },
})

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss(), polyfills()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
})
