import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { app, registerAndLogin } from '../helpers/api.js';
import { closeConnections, resetDatabase } from '../helpers/db.js';
import { prisma } from '../../src/lib/prisma.js';

beforeEach(resetDatabase);
afterAll(closeConnections);

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET as string;

describe('GET /api/v1/auth/me', () => {
  it('returns the authenticated user for a valid token', async () => {
    const { accessToken, userId } = await registerAndLogin('me@example.com');

    const response = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(response.status).toBe(200);
    expect(response.body.user).toMatchObject({ id: userId, email: 'me@example.com' });
    expect(response.body.user.passwordHash).toBeUndefined();
  });

  it('rejects a request with no Authorization header', async () => {
    const response = await request(app).get('/api/v1/auth/me');

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('UNAUTHORIZED');
  });

  it('rejects a token that is not sent as a Bearer token', async () => {
    const { accessToken } = await registerAndLogin('scheme@example.com');

    await request(app).get('/api/v1/auth/me').set('Authorization', accessToken).expect(401);
    await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Basic ${accessToken}`)
      .expect(401);
  });

  it('rejects a structurally invalid token', async () => {
    await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', 'Bearer not-a-jwt-at-all')
      .expect(401);
  });

  it('rejects an expired token', async () => {
    const { userId } = await registerAndLogin('expired@example.com');

    // Signed with the real secret but already past its expiry, which is the case
    // a short TTL exists to create.
    const expiredToken = jwt.sign({ sub: userId, role: 'USER', type: 'access' }, ACCESS_SECRET, {
      expiresIn: '-1s',
      issuer: process.env.JWT_ISSUER ?? 'auth-service',
      audience: process.env.JWT_AUDIENCE ?? 'auth-service-clients',
    });

    const response = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${expiredToken}`);

    expect(response.status).toBe(401);
  });

  it('rejects a token signed with the wrong secret', async () => {
    const { userId } = await registerAndLogin('forged@example.com');

    const forged = jwt.sign({ sub: userId, role: 'SUPERADMIN', type: 'access' }, 'attacker-secret', {
      expiresIn: '15m',
      issuer: process.env.JWT_ISSUER ?? 'auth-service',
      audience: process.env.JWT_AUDIENCE ?? 'auth-service-clients',
    });

    await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${forged}`)
      .expect(401);
  });

  it('rejects an unsigned ("alg": "none") token', async () => {
    const { userId } = await registerAndLogin('none@example.com');

    // The classic JWT attack: strip the signature and claim the algorithm is
    // "none". Pinning algorithms during verification is what blocks it.
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({
        sub: userId,
        role: 'SUPERADMIN',
        type: 'access',
        iss: process.env.JWT_ISSUER ?? 'auth-service',
        aud: process.env.JWT_AUDIENCE ?? 'auth-service-clients',
        exp: Math.floor(Date.now() / 1000) + 900,
      }),
    ).toString('base64url');

    await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${header}.${payload}.`)
      .expect(401);
  });

  it('rejects a token minted for a different audience', async () => {
    const { userId } = await registerAndLogin('audience@example.com');

    const wrongAudience = jwt.sign({ sub: userId, role: 'USER', type: 'access' }, ACCESS_SECRET, {
      expiresIn: '15m',
      issuer: process.env.JWT_ISSUER ?? 'auth-service',
      audience: 'some-other-service',
    });

    await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${wrongAudience}`)
      .expect(401);
  });

  it('rejects a valid token whose user has since been deleted', async () => {
    const { accessToken, userId } = await registerAndLogin('deleted@example.com');

    await prisma.user.delete({ where: { id: userId } });

    const response = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(response.status).toBe(401);
  });
});
