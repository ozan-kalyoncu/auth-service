import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse } from 'dotenv';
import { envSchema } from '../../src/config/env.js';

/**
 * `.env.example` is the file every new contributor copies to `.env`, and the one
 * docker-compose substitutes from. If it does not satisfy the schema, the
 * service refuses to boot -- correct behaviour, but a terrible first experience,
 * and the failure only shows up as a crash-looping container.
 */
const example = parse(readFileSync('.env.example', 'utf8'));

describe('.env.example', () => {
  it('parses once its secrets are filled in', () => {
    const result = envSchema.safeParse({
      ...example,
      // The two placeholders a human is told to replace.
      JWT_ACCESS_SECRET: 'a'.repeat(48),
      DATABASE_URL: example.DATABASE_URL,
    });

    expect(result.success).toBe(true);
  });

  it('treats the blank optional variables as absent, not invalid', () => {
    // These ship blank on purpose: OAuth providers are optional. `.optional()`
    // alone permits a MISSING key, not an empty one, so without normalisation
    // `OAUTH_SUCCESS_REDIRECT_URL=` fails url() and the process exits at boot.
    expect(example.GOOGLE_CLIENT_ID).toBe('');
    expect(example.OAUTH_SUCCESS_REDIRECT_URL).toBe('');

    const result = envSchema.safeParse({ ...example, JWT_ACCESS_SECRET: 'a'.repeat(48) });

    expect(result.success).toBe(true);
    expect(result.data?.GOOGLE_CLIENT_ID).toBeUndefined();
    expect(result.data?.OAUTH_SUCCESS_REDIRECT_URL).toBeUndefined();
  });

  it('lets a blank variable fall back to its default', () => {
    const result = envSchema.safeParse({
      ...example,
      JWT_ACCESS_SECRET: 'a'.repeat(48),
      OAUTH_CALLBACK_BASE_URL: '',
    });

    expect(result.data?.OAUTH_CALLBACK_BASE_URL).toBe('http://localhost:3000');
  });

  it('still rejects a genuinely malformed value', () => {
    // Normalising blanks must not turn into accepting nonsense.
    const result = envSchema.safeParse({
      ...example,
      JWT_ACCESS_SECRET: 'a'.repeat(48),
      OAUTH_SUCCESS_REDIRECT_URL: 'not-a-url',
    });

    expect(result.success).toBe(false);
  });

  it('still rejects a too-short signing secret', () => {
    const result = envSchema.safeParse({ ...example, JWT_ACCESS_SECRET: 'short' });

    expect(result.success).toBe(false);
  });

  it('documents every variable the schema knows about', () => {
    // Catches the other direction: a variable added to the schema but never
    // written down, which a new contributor then has no way to discover.
    const documented = new Set(Object.keys(example));
    const known = Object.keys(envSchema.shape);

    // NODE_ENV/PORT/LOG_LEVEL and the datastore URLs are all present in the file;
    // anything genuinely optional to document can be added to this allowance.
    const undocumented = known.filter((key) => !documented.has(key));

    expect(undocumented).toEqual([]);
  });
});
