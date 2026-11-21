import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { resolve } from 'node:path';

const routerTarget = process.env.AIOS_ROUTER_URL;

export default defineConfig({
  base: './',
  plugins: [vue()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src')
    }
  },
  build: {
    outDir: resolve(__dirname, '../packages/luci-app-aios/root/www/aios'),
    emptyOutDir: true,
    target: 'es2020',
    sourcemap: false
  },
  server: {
    port: 5173,
    proxy: routerTarget
      ? {
          '/ubus': {
            target: routerTarget,
            changeOrigin: true
          }
        }
      : undefined
  }
});
