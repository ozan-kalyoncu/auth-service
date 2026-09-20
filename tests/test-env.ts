/**
 * Test datastore URLs, in one place so global setup and the per-file setup
 * cannot drift apart and point at different databases.
 *
 * Both target a dedicated test database and a separate Redis logical DB, so
 * running the suite never wipes data being poked at by hand in Postman.
 */
export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgresql://auth:auth@localhost:5433/auth_test?schema=public';

export const TEST_REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://localhost:6380/1';
