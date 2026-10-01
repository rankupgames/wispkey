import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { viteSingleFile } from "vite-plugin-singlefile";

export default defineConfig({
  plugins: [svelte(), viteSingleFile()],
  base: "./",
  build: {
    // Preserve Vite 6's compile targets for native webviews. Vite 8's newer
    // defaults must not silently raise the embedded UI's platform baseline.
    target: ["chrome87", "edge88", "firefox78", "safari14"],
    outDir: "../ui-dist",
    emptyOutDir: true,
  },
});
