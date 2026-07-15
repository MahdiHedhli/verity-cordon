import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const daemonOrigin = "http://127.0.0.1:8765";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    strictPort: true,
    port: 5173,
    proxy: {
      "/api": {
        target: daemonOrigin,
        changeOrigin: true,
        configure(proxy) {
          proxy.on("proxyReq", (proxyRequest) => {
            proxyRequest.setHeader("Origin", daemonOrigin);
          });
        },
      },
    },
  },
  preview: {
    host: "127.0.0.1",
    strictPort: true,
  },
  build: {
    sourcemap: false,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: true,
    coverage: {
      reporter: ["text", "json-summary"],
    },
  },
});
