import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    setupFiles: ['tests/setup.ts'],

    // Integration tests share one Postgres and one Redis. Running files in
    // parallel would let one test's data race another's, so every file runs in
    // the same single worker. Slower, but deterministic; parallelism can come
    // back with per-worker database schemas if the suite ever gets slow enough
    // to matter.
    pool: 'forks',
    maxWorkers: 1,
    fileParallelism: false,
  },
});
