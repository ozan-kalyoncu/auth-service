import { execSync } from 'node:child_process';
import pg from 'pg';
import { TEST_DATABASE_URL } from './test-env.js';

/**
 * Runs ONCE before the whole suite.
 *
 * Integration tests run against a real Postgres rather than a mocked Prisma
 * client, because the things most worth testing here are exactly the things a
 * mock would fake away: the unique constraint on email, whether a migration
 * actually applied, how Prisma reports a duplicate key. The cost is this setup.
 */
export default async function globalSetup(): Promise<void> {
  await createTestDatabaseIfMissing();

  // `migrate deploy`, not `migrate dev`: it applies existing migrations without
  // prompting or generating new ones -- the right command for a non-interactive
  // environment, and the same one the Docker container runs on startup.
  execSync('npx prisma migrate deploy', {
    stdio: 'inherit',
    env: { ...process.env, DATABASE_URL: TEST_DATABASE_URL },
  });
}

/**
 * Creates the test database if it does not exist, so a fresh clone can run
 * `npm test` with no manual psql step.
 *
 * CREATE DATABASE cannot run inside a transaction or take a bind parameter, so
 * the name is interpolated -- it comes from our own config and never from user
 * input, but it is validated below anyway to keep that guarantee local.
 */
async function createTestDatabaseIfMissing(): Promise<void> {
  const url = new URL(TEST_DATABASE_URL);
  const databaseName = url.pathname.slice(1);

  if (!/^[A-Za-z0-9_]+$/.test(databaseName)) {
    throw new Error(`Refusing to create database with unexpected name: ${databaseName}`);
  }

  // Connect to the always-present `postgres` database to issue CREATE DATABASE.
  const adminUrl = new URL(TEST_DATABASE_URL);
  adminUrl.pathname = '/postgres';

  const client = new pg.Client({ connectionString: adminUrl.toString() });
  await client.connect();

  try {
    const existing = await client.query('SELECT 1 FROM pg_database WHERE datname = $1', [
      databaseName,
    ]);

    if (existing.rowCount === 0) {
      await client.query(`CREATE DATABASE "${databaseName}"`);
    }
  } finally {
    await client.end();
  }
}
