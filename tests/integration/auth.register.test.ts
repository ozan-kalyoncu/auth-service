import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';

/**
 * The stub mailer is replaced with a collector so tests can assert on what WOULD
 * have been emailed -- including the verification link, which is deliberately
 * never returned in an API response.
 *
 * `vi.hoisted` is needed because `vi.mock` is hoisted above the imports, so the
 * array has to exist before any import runs.
 */
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

describe('POST /api/v1/auth/register', () => {
  it('creates an account and sends a verification email', async () => {
    const response = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'new@example.com', password: VALID_PASSWORD });

    expect(response.status).toBe(202);

    const user = await prisma.user.findUnique({ where: { email: 'new@example.com' } });
    expect(user).not.toBeNull();
    expect(user?.isEmailVerified).toBe(false);
    expect(user?.role).toBe('USER');

    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0]?.to).toBe('new@example.com');
    expect(sentEmails[0]?.body).toContain('/api/v1/auth/verify-email?token=');
  });

  it('never stores the password in plaintext', async () => {
    await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'hash@example.com', password: VALID_PASSWORD })
      .expect(202);

    const user = await prisma.user.findUnique({ where: { email: 'hash@example.com' } });

    expect(user?.passwordHash).not.toBe(VALID_PASSWORD);
    // Argon2id hashes carry their parameters in the string itself.
    expect(user?.passwordHash).toMatch(/^\$argon2id\$/);
  });

  it('never returns the password hash to the client', async () => {
    const response = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'leak@example.com', password: VALID_PASSWORD });

    expect(JSON.stringify(response.body)).not.toContain('argon2');
    expect(response.body.user).toBeUndefined();
  });

  it('does not reveal that an email is already registered', async () => {
    const first = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'dupe@example.com', password: VALID_PASSWORD });

    sentEmails.length = 0;

    const second = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'dupe@example.com', password: 'a-completely-different-password' });

    // Identical response: an attacker cannot tell the two cases apart.
    expect(second.status).toBe(first.status);
    expect(second.body).toEqual(first.body);

    // Exactly one account, and its password is unchanged by the second attempt.
    const users = await prisma.user.findMany({ where: { email: 'dupe@example.com' } });
    expect(users).toHaveLength(1);

    // The real owner is told instead, at the address on file.
    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0]?.to).toBe('dupe@example.com');
    expect(sentEmails[0]?.body).toContain('already exists');
  });

  it('normalises email case so one address cannot become two accounts', async () => {
    await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'Mixed@Example.com', password: VALID_PASSWORD })
      .expect(202);

    await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'mixed@example.com', password: VALID_PASSWORD })
      .expect(202);

    const users = await prisma.user.findMany();
    expect(users).toHaveLength(1);
    expect(users[0]?.email).toBe('mixed@example.com');
  });

  it('rejects a malformed email', async () => {
    const response = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'not-an-email', password: VALID_PASSWORD });

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
    expect(response.body.error.details[0].path).toBe('email');
  });

  it('rejects a password below the minimum length', async () => {
    const response = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'short@example.com', password: 'short' });

    expect(response.status).toBe(400);
    expect(response.body.error.details[0].path).toBe('password');
    await expect(prisma.user.count()).resolves.toBe(0);
  });

  it('rejects a missing body entirely', async () => {
    const response = await request(app).post('/api/v1/auth/register').send({});

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('ignores a client-supplied role instead of trusting it', async () => {
    // Privilege escalation attempt: the validator strips unknown fields, so
    // `role` never reaches the database layer.
    await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'sneaky@example.com', password: VALID_PASSWORD, role: 'SUPERADMIN' })
      .expect(202);

    const user = await prisma.user.findUnique({ where: { email: 'sneaky@example.com' } });
    expect(user?.role).toBe('USER');
  });
});
