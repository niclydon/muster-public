import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['packages/*/test/**/*.test.ts', 'scripts/test/**/*.test.ts'],
    // Integration suites share one Postgres database and reset it per file.
    fileParallelism: false,
    testTimeout: 20_000,
    // Reset applies four production-shaped schema fixtures; on the shared
    // scratch cluster that can legitimately exceed the default 10s hook cap.
    hookTimeout: 60_000,
  },
});
