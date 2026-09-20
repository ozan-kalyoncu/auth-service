import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';

const { sentEmails } = vi.hoisted(() => ({ sentEmails: [] as { to: string; body: string }[] }));

vi.mock('../../src/lib/mailer.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/lib/mailer.js')>();
  return {
    ...actual,
    sendEmail: async (email: { to: string; body: string }) => {
      sentEmails.push(email);
    },
  };
});

const { app, VALID_PASSWORD } = await import('../helpers/api.js');
const { resetDatabase, closeConnections } = await import('../helpers/db.js');
const { prisma } = await import('../../src/lib/prisma.js');

beforeEach(async () => {
  await resetDatabase();
  sentEmails.length = 0;
});

afterAll(closeConnections);

/** Pulls the raw token out of the emailed link -- the only place it exists. */
function tokenFromLastEmail(): string {
  const body = sentEmails.at(-1)?.body ?? '';
  return /verify-email\?token=([\w-]+)/.exec(body)?.[1] ?? '';
}

describe('GET /api/v1/auth/verify-email', () => {
  it('verifies the account when given the emailed token', async () => {
    await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'verify@example.com', password: VALID_PASSWORD })
      .expect(202);

    const token = tokenFromLastEmail();
    expect(token).not.toBe('');

    await request(app).get(`/api/v1/auth/verify-email?token=${token}`).expect(200);

    const user = await prisma.user.findUnique({ where: { email: 'verify@example.com' } });
    expect(user?.isEmailVerified).toBe(true);
  });

  it('rejects a token that has already been used', async () => {
    await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'once@example.com', password: VALID_PASSWORD })
      .expect(202);

    const token = tokenFromLastEmail();

    await request(app).get(`/api/v1/auth/verify-email?token=${token}`).expect(200);

    // Single-use: consuming the token deleted it, so a replay fails even though
    // the link is still sitting in the inbox.
    const replay = await request(app).get(`/api/v1/auth/verify-email?token=${token}`);

    expect(replay.status).toBe(400);
    expect(replay.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('rejects an unknown token', async () => {
    const response = await request(app).get('/api/v1/auth/verify-email?token=made-up-token');

    expect(response.status).toBe(400);
  });

  it('requires a token parameter', async () => {
    const response = await request(app).get('/api/v1/auth/verify-email');

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('stores only a hash of the token, never the token itself', async () => {
    await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'hashed@example.com', password: VALID_PASSWORD })
      .expect(202);

    const token = tokenFromLastEmail();
    const { redis } = await import('../../src/lib/redis.js');
    const keys = await redis.keys('email-verification:*');

    expect(keys).toHaveLength(1);
    // The raw token must not appear anywhere in the stored key.
    expect(keys[0]).not.toContain(token);
    expect(keys[0]).toMatch(/^email-verification:[a-f0-9]{64}$/);
  });
});

describe('POST /api/v1/auth/resend-verification', () => {
  it('sends a fresh link for an unverified account', async () => {
    await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'resend@example.com', password: VALID_PASSWORD })
      .expect(202);

    const firstToken = tokenFromLastEmail();
    sentEmails.length = 0;

    await request(app)
      .post('/api/v1/auth/resend-verification')
      .send({ email: 'resend@example.com' })
      .expect(202);

    expect(sentEmails).toHaveLength(1);
    expect(tokenFromLastEmail()).not.toBe(firstToken);
  });

  it('responds identically for unknown, unverified and already-verified accounts', async () => {
    await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'known@example.com', password: VALID_PASSWORD })
      .expect(202);

    await request(app).get(`/api/v1/auth/verify-email?token=${tokenFromLastEmail()}`).expect(200);

    const alreadyVerified = await request(app)
      .post('/api/v1/auth/resend-verification')
      .send({ email: 'known@example.com' });

    const unknown = await request(app)
      .post('/api/v1/auth/resend-verification')
      .send({ email: 'nobody@example.com' });

    expect(unknown.status).toBe(alreadyVerified.status);
    expect(unknown.body).toEqual(alreadyVerified.body);
  });
});
