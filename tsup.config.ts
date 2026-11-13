import { defineConfig } from "tsup";

// Publishable build: bundle .ts-specifier source → Node ESM + bundled .d.ts.
// @k9o/* siblings + third-party deps auto-externalised from package.json deps.
export default defineConfig({
  entry: [
    "src/index.ts",
    "src/types.ts",
  ],
  format: ["esm"],
  target: "node18",
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: true,
});
