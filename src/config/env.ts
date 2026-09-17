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
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  // 'silent' disables logging entirely -- used by the test suite so assertion
  // output is not buried under request logs.
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),

  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  REDIS_URL: z.string().min(1, 'REDIS_URL is required'),

  // 32 chars is a floor, not a recommendation -- use `openssl rand -base64 48`.
  // Short secrets are brute-forceable offline once an attacker has one signed token.
  JWT_ACCESS_SECRET: z.string().min(32, 'JWT_ACCESS_SECRET must be at least 32 characters'),
  JWT_REFRESH_SECRET: z.string().min(32, 'JWT_REFRESH_SECRET must be at least 32 characters'),
  JWT_ACCESS_TTL: z.string().default('15m'),
  JWT_REFRESH_TTL: z.string().default('7d'),
  JWT_ISSUER: z.string().default('auth-service'),
  JWT_AUDIENCE: z.string().default('auth-service-clients'),

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

  // Optional until milestone 5 (OAuth2). Absent means "provider not configured",
  // which the OAuth routes will treat as disabled rather than crashing.
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  GITHUB_CLIENT_ID: z.string().optional(),
  GITHUB_CLIENT_SECRET: z.string().optional(),
  OAUTH_CALLBACK_BASE_URL: z.url().default('http://localhost:3000'),
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
