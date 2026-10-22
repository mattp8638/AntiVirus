import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev, proxy API calls to Fenrir Cloud on :8080.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": "http://localhost:8080", "/dns": "http://localhost:8080", "/install": "http://localhost:8080" },
  },
  build: { outDir: "dist", sourcemap: false },
});
