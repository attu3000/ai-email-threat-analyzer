import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "./",
  plugins: [react()],
  build: {
    outDir: "extension/dist",
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: "extension/popup.html"
      }
    }
  }
});