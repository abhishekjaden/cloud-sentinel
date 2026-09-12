import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // auth.ts touches sessionStorage, window.location, btoa and crypto.subtle,
    // so it needs a browser-like environment rather than bare Node.
    environment: "jsdom",
    globals: true,
    coverage: {
      provider: "v8",
      include: ["src/auth.ts", "src/api.ts", "src/config.ts"],
      reporter: ["text", "lcov"],
    },
  },
});
