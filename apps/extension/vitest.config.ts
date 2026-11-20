import { defineConfig } from "vitest/config";

export default defineConfig({
  // What scripts/build.mjs defines; the unit tests run as Chromium.
  define: { __TARGET__: JSON.stringify("chromium") },
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    setupFiles: ["test/setup.ts"],
  },
});
