import 'dotenv/config';
import { z } from 'zod';

/**
 * Environment variables are parsed ONCE here, at startup, through a Zod schema.
 *
 * The alternative -- reading `process.env.X` wherever it is needed -- means a
 * missing or malformed secret surfaces as an undefined value deep inside a
 * request, hours after deploy. Validating up front turns that into a loud crash
 * before the server ever accepts traffic ("fail fast"), and gives the rest of the
 * codebase a fully typed config object instead of `string | undefined` everywhere.
 */

/**
 * Treats a blank variable as absent.
 *
 * `.optional()` permits a MISSING key, not an empty one -- so `FOO=` in a .env
 * file still arrives as `""` and fails a url() or min() check. That distinction
 * is invisible to whoever is editing the file: a commented-out placeholder left
 * blank is plainly meant as "not configured", and should also let a `.default()`
 * apply. Normalising here keeps every optional variable honest, rather than
 * patching each one the first time it breaks a deploy.
 */
function blankToUndefined<T extends z.ZodTypeAny>(schema: T) {
  return z.preprocess(
    (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
    schema,
  );
}

// Exported so a test can check the committed .env.example still parses, rather
// than that being discovered by a container crash-looping on startup.
export const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  // 'silent' disables logging entirely -- used by the test suite so assertion
  // output is not buried under request logs.
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),

  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  REDIS_URL: z.string().min(1, 'REDIS_URL is required'),

  // 32 chars is a floor, not a recommendation -- use `openssl rand -base64 48`.
  // Short secrets are brute-forceable offline once an attacker has one signed token.
  //
  // Only ACCESS tokens are signed. Refresh tokens are opaque random strings
  // looked up in the database, so there is deliberately no refresh secret here.
  JWT_ACCESS_SECRET: z.string().min(32, 'JWT_ACCESS_SECRET must be at least 32 characters'),
  JWT_ACCESS_TTL: z.string().default('15m'),
  JWT_REFRESH_TTL: z.string().default('7d'),
  JWT_ISSUER: z.string().default('auth-service'),
  JWT_AUDIENCE: z.string().default('auth-service-clients'),

  // Public base URL of this service, used to build links that land in emails
  // (verification, and password reset later). It cannot be derived from the
  // request host: that header is attacker-controlled, and trusting it lets
  // someone request a verification email containing a link to their own domain.
  APP_BASE_URL: blankToUndefined(z.url().default('http://localhost:3000')),

  // Stored in .env as a comma-separated string; transformed into an array here so
  // no consumer has to remember the encoding.
  CORS_ORIGINS: z
    .string()
    .default('')
    .transform((value) =>
      value
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean),
    ),

  // Absent (or blank) means "provider not configured", which the OAuth routes
  // treat as "this deployment does not offer it" rather than crashing. That is
  // why these are normalised: `.env.example` ships them blank on purpose.
  GOOGLE_CLIENT_ID: blankToUndefined(z.string().optional()),
  GOOGLE_CLIENT_SECRET: blankToUndefined(z.string().optional()),
  GITHUB_CLIENT_ID: blankToUndefined(z.string().optional()),
  GITHUB_CLIENT_SECRET: blankToUndefined(z.string().optional()),
  OAUTH_CALLBACK_BASE_URL: blankToUndefined(z.url().default('http://localhost:3000')),

  // Where to send the browser after a successful OAuth sign-in. When set, the
  // callback sets the refresh cookie and redirects here WITHOUT putting any
  // token in the URL -- the app then calls /auth/refresh for an access token.
  // Left unset (the default), the callback returns JSON instead, which is what
  // makes the flow demonstrable with curl in a service that has no frontend.
  OAUTH_SUCCESS_REDIRECT_URL: blankToUndefined(z.url().optional()),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  // Printed rather than thrown as a raw ZodError so the failure is readable in a
  // container log: one line per bad variable, and never the value itself.
  const issues = parsed.error.issues
    .map((issue) => `  - ${issue.path.join('.')}: ${issue.message}`)
    .join('\n');

  console.error(`Invalid environment configuration:\n${issues}`);
  process.exit(1);
}

export const env = parsed.data;

export const isProduction = env.NODE_ENV === 'production';
export const isTest = env.NODE_ENV === 'test';
