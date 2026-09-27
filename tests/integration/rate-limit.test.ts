import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { app, registerUser, VALID_PASSWORD } from '../helpers/api.js';
import { closeConnections, resetDatabase } from '../helpers/db.js';
import { BRUTE_FORCE, RATE_LIMITS } from '../../src/config/constants.js';
import { redis } from '../../src/lib/redis.js';

// resetDatabase also flushes Redis, so every test starts with empty counters.
beforeEach(resetDatabase);
afterAll(closeConnections);

const WRONG_PASSWORD = 'definitely-not-the-password';

describe('per-IP rate limiting', () => {
  it('advertises the limit on every response, not just rejections', async () => {
    await registerUser('headers@example.com');

    const response = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'headers@example.com', password: VALID_PASSWORD })
      .expect(200);

    // A client can slow down before being cut off rather than discovering the
    // limit by hitting it.
    expect(response.headers['ratelimit-limit']).toBe(String(RATE_LIMITS.login.limit));
    expect(Number(response.headers['ratelimit-remaining'])).toBe(RATE_LIMITS.login.limit - 1);
    expect(Number(response.headers['ratelimit-reset'])).toBeGreaterThan(0);
  });

  it('blocks registration past the limit and says when to retry', async () => {
    const { limit } = RATE_LIMITS.register;

    for (let i = 0; i < limit; i += 1) {
      await request(app)
        .post('/api/v1/auth/register')
        .send({ email: `bulk${i}@example.com`, password: VALID_PASSWORD })
        .expect(202);
    }

    const blocked = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'one-too-many@example.com', password: VALID_PASSWORD });

    expect(blocked.status).toBe(429);
    expect(blocked.body.error.code).toBe('RATE_LIMITED');
    // Turns "try again later" into a number, so retries do not become their own
    // small denial of service.
    expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);

    // The blocked request did no work.
    const { prisma } = await import('../../src/lib/prisma.js');
    await expect(
      prisma.user.findUnique({ where: { email: 'one-too-many@example.com' } }),
    ).resolves.toBeNull();
  });

  it('counts rejected requests too, so malformed input is not a free pass', async () => {
    const { limit } = RATE_LIMITS.register;

    // Garbage bodies still consume quota -- otherwise an attacker could hammer
    // the endpoint indefinitely just by sending invalid payloads.
    for (let i = 0; i < limit; i += 1) {
      await request(app).post('/api/v1/auth/register').send({ nonsense: true }).expect(400);
    }

    await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'valid@example.com', password: VALID_PASSWORD })
      .expect(429);
  });

  it('keeps separate counters per endpoint', async () => {
    const { limit } = RATE_LIMITS.resendVerification;

    for (let i = 0; i < limit; i += 1) {
      await request(app)
        .post('/api/v1/auth/resend-verification')
        .send({ email: 'someone@example.com' })
        .expect(202);
    }

    await request(app)
      .post('/api/v1/auth/resend-verification')
      .send({ email: 'someone@example.com' })
      .expect(429);

    // A different endpoint is unaffected: one bucket per route.
    await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'unrelated@example.com', password: VALID_PASSWORD })
      .expect(202);
  });

  it('limits the OAuth start endpoint', async () => {
    const { limit } = RATE_LIMITS.oauthStart;

    for (let i = 0; i < limit; i += 1) {
      await request(app).get('/api/v1/auth/oauth/google').expect(302);
    }

    await request(app).get('/api/v1/auth/oauth/google').expect(429);
  });
});

describe('per-account brute-force protection', () => {
  async function failLogin(email: string): Promise<request.Response> {
    return request(app).post('/api/v1/auth/login').send({ email, password: WRONG_PASSWORD });
  }

  it('locks an account after repeated failures and unlocks on its own', async () => {
    await registerUser('target@example.com');

    // Under the threshold: ordinary 401s, nothing special.
    for (let i = 0; i < BRUTE_FORCE.threshold - 1; i += 1) {
      const response = await failLogin('target@example.com');
      expect(response.status).toBe(401);
    }

    // The failure that trips the lock still reports 401 -- the lock applies from
    // the NEXT attempt.
    expect((await failLogin('target@example.com')).status).toBe(401);

    const locked = await failLogin('target@example.com');
    expect(locked.status).toBe(429);
    expect(locked.body.error.code).toBe('RATE_LIMITED');
    expect(locked.body.error.details.retryAfterSeconds).toBeGreaterThan(0);

    // Even the CORRECT password is refused while the lock holds. That is the
    // point: an attacker who eventually guesses right still cannot get in.
    const correctButLocked = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'target@example.com', password: VALID_PASSWORD });
    expect(correctButLocked.status).toBe(429);

    // Expiring the lock stands in for waiting out the backoff.
    const { hashToken } = await import('../../src/lib/crypto.js');
    await redis.del(`bruteforce:lock:${hashToken('target@example.com')}`);

    await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'target@example.com', password: VALID_PASSWORD })
      .expect(200);
  });

  it('backs off exponentially rather than locking forever', async () => {
    await registerUser('backoff@example.com');
    const { hashToken } = await import('../../src/lib/crypto.js');
    const key = `bruteforce:lock:${hashToken('backoff@example.com')}`;

    for (let i = 0; i < BRUTE_FORCE.threshold; i += 1) {
      await failLogin('backoff@example.com');
    }
    const firstLock = await redis.ttl(key);

    // Clear the lock and fail once more: the next lock should be longer.
    await redis.del(key);
    await failLogin('backoff@example.com');
    const secondLock = await redis.ttl(key);

    expect(firstLock).toBeLessThanOrEqual(BRUTE_FORCE.baseLockSeconds);
    expect(secondLock).toBeGreaterThan(firstLock);
    // A permanent lock would let anyone who knows your email lock you out for
    // good, so the backoff is capped.
    expect(secondLock).toBeLessThanOrEqual(BRUTE_FORCE.maxLockSeconds);
  });

  it('forgives the run of failures after a successful login', async () => {
    await registerUser('forgiven@example.com');

    for (let i = 0; i < BRUTE_FORCE.threshold - 1; i += 1) {
      await failLogin('forgiven@example.com');
    }

    await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'forgiven@example.com', password: VALID_PASSWORD })
      .expect(200);

    const { hashToken } = await import('../../src/lib/crypto.js');
    await expect(redis.get(`bruteforce:failures:${hashToken('forgiven@example.com')}`)).resolves
      .toBeNull();

    // Back to a clean slate: one more failure is just a 401.
    expect((await failLogin('forgiven@example.com')).status).toBe(401);
  });

  it('locks an unknown email the same way, so lockout is not an oracle', async () => {
    // If only real accounts could be locked, the difference between 401 and 429
    // would reveal which addresses exist.
    for (let i = 0; i <= BRUTE_FORCE.threshold; i += 1) {
      await failLogin('ghost@example.com');
    }

    const response = await failLogin('ghost@example.com');
    expect(response.status).toBe(429);
  });

  it('does not lock a different account', async () => {
    await registerUser('victim@example.com');
    await registerUser('bystander@example.com');

    for (let i = 0; i <= BRUTE_FORCE.threshold; i += 1) {
      await failLogin('victim@example.com');
    }

    expect((await failLogin('victim@example.com')).status).toBe(429);

    await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'bystander@example.com', password: VALID_PASSWORD })
      .expect(200);
  });

  it('checks the lock before doing any expensive work', async () => {
    await registerUser('cheap@example.com');

    for (let i = 0; i <= BRUTE_FORCE.threshold; i += 1) {
      await failLogin('cheap@example.com');
    }

    const { prisma } = await import('../../src/lib/prisma.js');
    const before = await prisma.loginAttempt.count();

    await failLogin('cheap@example.com').then((r) => expect(r.status).toBe(429));

    // A locked request is rejected before the password check and before the
    // audit write -- it costs one Redis read, not an Argon2 verification.
    await expect(prisma.loginAttempt.count()).resolves.toBe(before);
  });
});
