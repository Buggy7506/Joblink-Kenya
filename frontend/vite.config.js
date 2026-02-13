import { defineConfig } from "vite";

export default defineConfig({
  build: {
    lib: {
      entry: "main.js",
      name: "CanvaApp",
      formats: ["iife"]
    },
    rollupOptions: {
      output: {
        inlineDynamicImports: true
      }
    }
  }
});
