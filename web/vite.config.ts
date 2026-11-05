import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The production build is mounted by FastAPI at /static/web/.
// `npm run dev` keeps the root path so local previews stay simple.
export default defineConfig(({ command }) => ({
  base: command === "build" ? "/static/web/" : "/",
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8082",
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    chunkSizeWarningLimit: 1800,
  },
}));
