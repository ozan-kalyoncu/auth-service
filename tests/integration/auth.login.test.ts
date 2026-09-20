import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { app, registerUser, VALID_PASSWORD } from '../helpers/api.js';
import { closeConnections, resetDatabase } from '../helpers/db.js';
import { prisma } from '../../src/lib/prisma.js';

beforeEach(resetDatabase);
afterAll(closeConnections);

describe('POST /api/v1/auth/login', () => {
  it('returns an access token and the public user for valid credentials', async () => {
    await registerUser('user@example.com');

    const response = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'user@example.com', password: VALID_PASSWORD });

    expect(response.status).toBe(200);
    expect(response.body.tokenType).toBe('Bearer');
    expect(response.body.expiresIn).toBe(900); // 15m, from JWT_ACCESS_TTL
    expect(typeof response.body.accessToken).toBe('string');

    expect(response.body.user).toMatchObject({
      email: 'user@example.com',
      role: 'USER',
      isEmailVerified: false,
    });

    // The public user shape must never carry the hash.
    expect(response.body.user.passwordHash).toBeUndefined();
  });

  it('accepts a differently-cased email', async () => {
    await registerUser('case@example.com');

    await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'CASE@Example.COM', password: VALID_PASSWORD })
      .expect(200);
  });

  it('rejects a wrong password', async () => {
    await registerUser('user@example.com');

    const response = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'user@example.com', password: 'wrong-password-entirely' });

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('UNAUTHORIZED');
    expect(response.body.accessToken).toBeUndefined();
  });

  it('gives an identical response for an unknown email and a wrong password', async () => {
    await registerUser('real@example.com');

    const wrongPassword = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'real@example.com', password: 'wrong-password-entirely' });

    const unknownEmail = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'ghost@example.com', password: 'wrong-password-entirely' });

    // Identical status and body: the endpoint cannot be used to discover which
    // email addresses have accounts.
    expect(unknownEmail.status).toBe(wrongPassword.status);
    expect(unknownEmail.body).toEqual(wrongPassword.body);
  });

  it('records both successful and failed attempts for the audit trail', async () => {
    await registerUser('audit@example.com');

    await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'audit@example.com', password: 'wrong-password-entirely' })
      .expect(401);

    await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'audit@example.com', password: VALID_PASSWORD })
      .expect(200);

    const attempts = await prisma.loginAttempt.findMany({ orderBy: { createdAt: 'asc' } });

    expect(attempts).toHaveLength(2);
    expect(attempts[0]?.success).toBe(false);
    expect(attempts[1]?.success).toBe(true);
    expect(attempts[0]?.ip).toBeTruthy();
  });

  it('records an attempt for an unknown email with a null userId', async () => {
    await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'ghost@example.com', password: VALID_PASSWORD })
      .expect(401);

    const attempts = await prisma.loginAttempt.findMany();

    expect(attempts).toHaveLength(1);
    expect(attempts[0]?.userId).toBeNull();
    expect(attempts[0]?.success).toBe(false);
  });

  it('rejects an OAuth-only account that has no password set', async () => {
    // Simulates the milestone 5 case: a user created through Google, with a null
    // passwordHash. Logging in with a password must fail like any other bad
    // credential rather than crashing on the null.
    await prisma.user.create({ data: { email: 'oauth@example.com', passwordHash: null } });

    const response = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'oauth@example.com', password: VALID_PASSWORD });

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('UNAUTHORIZED');
  });

  it('rejects an empty password without reaching the password check', async () => {
    const response = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'user@example.com', password: '' });

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });
});
