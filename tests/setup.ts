/**
 * Runs before every test file.
 *
 * Config is set here, ahead of any import of src/config/env.ts, because that
 * module validates process.env at import time and would exit the test runner if
 * a required secret were missing.
 */
process.env.NODE_ENV = 'test';
process.env.JWT_ACCESS_SECRET ??= 'test-access-secret-that-is-long-enough-32';
process.env.JWT_REFRESH_SECRET ??= 'test-refresh-secret-that-is-long-enough-32';
// Separate database and Redis logical DB from development, so running the suite
// never wipes data being used by hand in Postman.
process.env.DATABASE_URL ??= 'postgresql://auth:auth@localhost:5433/auth_test?schema=public';
process.env.REDIS_URL ??= 'redis://localhost:6380/1';
process.env.LOG_LEVEL = 'silent';
