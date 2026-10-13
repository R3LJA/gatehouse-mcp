import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 20_000,
    // each test file builds its own keys and data directory; files can run in parallel
    pool: "forks",
  },
});
