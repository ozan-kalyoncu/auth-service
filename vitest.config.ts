import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    setupFiles: ['tests/setup.ts'],

    // Creates and migrates the test database once for the whole run.
    globalSetup: ['tests/global-setup.ts'],

    // Argon2 is deliberately slow (~50ms per hash) and several tests register
    // users, so the default 5s timeout is tight on a cold run.
    testTimeout: 20_000,
    hookTimeout: 60_000,

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
