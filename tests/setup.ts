import { TEST_DATABASE_URL, TEST_REDIS_URL } from './test-env.js';

/**
 * Runs before every test file.
 *
 * Config is set here, ahead of any import of src/config/env.ts, because that
 * module validates process.env at import time and would exit the test runner if
 * a required secret were missing.
 */
process.env.NODE_ENV = 'test';
process.env.JWT_ACCESS_SECRET ??= 'test-access-secret-that-is-long-enough-32';
process.env.DATABASE_URL = TEST_DATABASE_URL;
process.env.REDIS_URL = TEST_REDIS_URL;
process.env.APP_BASE_URL = 'http://localhost:3000';
process.env.LOG_LEVEL = 'silent';

// Google is configured for tests; GitHub deliberately is not, so the
// "provider not available on this deployment" path has something to exercise.
// A test file that needs GitHub sets its credentials before importing the app
// (see tests/integration/oauth.test.ts).
process.env.GOOGLE_CLIENT_ID ??= 'test-google-client-id';
process.env.GOOGLE_CLIENT_SECRET ??= 'test-google-client-secret';
process.env.OAUTH_CALLBACK_BASE_URL ??= 'http://localhost:3000';
