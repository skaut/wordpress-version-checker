import { builtinModules } from "node:module";
import { defineConfig } from "vite";

const NODE_BUILT_IN_MODULES = builtinModules.filter((m) => !m.startsWith("_"));
NODE_BUILT_IN_MODULES.push(...NODE_BUILT_IN_MODULES.map((m) => `node:${m}`));

export default defineConfig({
  build: {
    emptyOutDir: false,
    lib: {
      entry: "src/index",
      fileName: "index",
      formats: ["es"],
    },
    rollupOptions: {
      external: NODE_BUILT_IN_MODULES,
    },
  },
  optimizeDeps: {
    exclude: NODE_BUILT_IN_MODULES,
  },
});
