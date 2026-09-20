import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { app, registerUser, VALID_PASSWORD } from '../helpers/api.js';
import { closeConnections, resetDatabase } from '../helpers/db.js';
import { prisma } from '../../src/lib/prisma.js';
import { hashToken } from '../../src/lib/crypto.js';

beforeEach(resetDatabase);
afterAll(closeConnections);

/**
 * Pulls the raw refresh token out of the Set-Cookie header. It is deliberately
 * absent from the JSON body, so this is the only way a client sees it.
 */
function refreshTokenFromResponse(response: request.Response): string {
  const cookies = response.headers['set-cookie'] as unknown as string[] | undefined;
  const cookie = cookies?.find((value) => value.startsWith('refresh_token='));

  return cookie?.split(';')[0]?.split('=')[1] ?? '';
}

async function loginAndGetRefreshToken(email: string): Promise<string> {
  await registerUser(email);

  const response = await request(app)
    .post('/api/v1/auth/login')
    .send({ email, password: VALID_PASSWORD })
    .expect(200);

  return refreshTokenFromResponse(response);
}

describe('refresh token issuing', () => {
  it('sets an httpOnly, path-scoped cookie on login and keeps it out of the body', async () => {
    await registerUser('cookie@example.com');

    const response = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'cookie@example.com', password: VALID_PASSWORD })
      .expect(200);

    const cookies = response.headers['set-cookie'] as unknown as string[];
    const cookie = cookies.find((value) => value.startsWith('refresh_token='));

    expect(cookie).toBeDefined();
    // httpOnly is what puts the token out of reach of page JavaScript.
    expect(cookie).toContain('HttpOnly');
    // SameSite=Strict blocks CSRF against the refresh endpoint.
    expect(cookie).toContain('SameSite=Strict');
    // Scoped so it is not attached to every request to the API.
    expect(cookie).toContain('Path=/api/v1/auth');

    // The body must never carry it -- that is the whole point of the cookie.
    expect(response.body.refreshToken).toBeUndefined();
    expect(JSON.stringify(response.body)).not.toContain(refreshTokenFromResponse(response));
  });

  it('stores only a hash of the refresh token', async () => {
    const rawToken = await loginAndGetRefreshToken('hashed@example.com');

    const stored = await prisma.refreshToken.findMany();

    expect(stored).toHaveLength(1);
    expect(stored[0]?.tokenHash).not.toBe(rawToken);
    expect(stored[0]?.tokenHash).toBe(hashToken(rawToken));
    expect(stored[0]?.revokedAt).toBeNull();
  });
});

describe('POST /api/v1/auth/refresh', () => {
  it('issues a new access token and a new refresh token', async () => {
    const firstToken = await loginAndGetRefreshToken('rotate@example.com');

    const response = await request(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', `refresh_token=${firstToken}`)
      .expect(200);

    const secondToken = refreshTokenFromResponse(response);

    expect(typeof response.body.accessToken).toBe('string');
    expect(secondToken).not.toBe(firstToken);
    expect(response.body.user.email).toBe('rotate@example.com');
  });

  it('records the rotation chain instead of deleting the spent token', async () => {
    const firstToken = await loginAndGetRefreshToken('chain@example.com');

    const response = await request(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', `refresh_token=${firstToken}`)
      .expect(200);

    const secondToken = refreshTokenFromResponse(response);

    const spent = await prisma.refreshToken.findUnique({
      where: { tokenHash: hashToken(firstToken) },
    });
    const replacement = await prisma.refreshToken.findUnique({
      where: { tokenHash: hashToken(secondToken) },
    });

    // The old row survives, revoked, pointing at its successor. That audit trail
    // is what makes reuse detectable rather than just "unknown token".
    expect(spent?.revokedAt).not.toBeNull();
    expect(spent?.replacedBy).toBe(replacement?.id);
    expect(replacement?.revokedAt).toBeNull();
  });

  it('accepts the token in the body for clients without a cookie jar', async () => {
    const token = await loginAndGetRefreshToken('nocookie@example.com');

    await request(app).post('/api/v1/auth/refresh').send({ refreshToken: token }).expect(200);
  });

  it('returns an access token that works on a protected route', async () => {
    const token = await loginAndGetRefreshToken('usable@example.com');

    const refreshed = await request(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', `refresh_token=${token}`)
      .expect(200);

    const me = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${refreshed.body.accessToken}`)
      .expect(200);

    expect(me.body.user.email).toBe('usable@example.com');
  });

  it('rejects a request with no refresh token at all', async () => {
    const response = await request(app).post('/api/v1/auth/refresh').send({});

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('UNAUTHORIZED');
  });

  it('rejects an unknown token', async () => {
    await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: 'never-issued-by-us' })
      .expect(401);
  });

  it('rejects an expired token and revokes it', async () => {
    const token = await loginAndGetRefreshToken('expired@example.com');

    // Backdate the expiry rather than waiting seven days.
    await prisma.refreshToken.update({
      where: { tokenHash: hashToken(token) },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });

    const response = await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: token });

    expect(response.status).toBe(401);
    expect(response.body.error.message).toContain('expired');

    // Revoked on the way out, so presenting it later reads as reuse rather than
    // as an unknown token.
    const stored = await prisma.refreshToken.findUnique({
      where: { tokenHash: hashToken(token) },
    });
    expect(stored?.revokedAt).not.toBeNull();
  });
});

describe('refresh token reuse detection', () => {
  it('revokes every session when an already-used token is presented again', async () => {
    const stolenToken = await loginAndGetRefreshToken('victim@example.com');

    // A second, independent session for the same user -- a different device.
    const secondLogin = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'victim@example.com', password: VALID_PASSWORD })
      .expect(200);
    const otherDeviceToken = refreshTokenFromResponse(secondLogin);

    // The legitimate user refreshes first, spending the token.
    const rotated = await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: stolenToken })
      .expect(200);
    const legitimateToken = refreshTokenFromResponse(rotated);

    // Now the thief presents the copy they stole earlier. It has been spent.
    const reuse = await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: stolenToken });

    expect(reuse.status).toBe(401);
    expect(reuse.body.error.message).toContain('already been used');

    // Because we cannot tell thief from victim, EVERY session is cut, including
    // the legitimate one just issued and the unrelated second device.
    const live = await prisma.refreshToken.findMany({ where: { revokedAt: null } });
    expect(live).toHaveLength(0);

    await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: legitimateToken })
      .expect(401);

    await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: otherDeviceToken })
      .expect(401);
  });

  it('does not touch other users when one account is compromised', async () => {
    const victimToken = await loginAndGetRefreshToken('compromised@example.com');
    const bystanderToken = await loginAndGetRefreshToken('bystander@example.com');

    await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: victimToken })
      .expect(200);

    await request(app).post('/api/v1/auth/refresh').send({ refreshToken: victimToken }).expect(401);

    // The blast radius stops at the affected account.
    await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: bystanderToken })
      .expect(200);
  });

  it('rejects a logged-out token without raising the theft alarm', async () => {
    const token = await loginAndGetRefreshToken('loggedout@example.com');

    await request(app).post('/api/v1/auth/logout').send({ refreshToken: token }).expect(204);

    const response = await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: token });

    // A deliberately revoked token was never SPENT in a rotation, so this is a
    // stale client rather than a stolen credential: rejected, but not treated as
    // reuse and not escalated to revoking the account's other sessions.
    expect(response.status).toBe(401);
    expect(response.body.error.message).toContain('revoked');
    expect(response.body.error.message).not.toContain('already been used');
  });

  it('does not re-raise the alarm for sessions killed by an earlier reuse cascade', async () => {
    const stolen = await loginAndGetRefreshToken('flood@example.com');

    const otherDevice = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'flood@example.com', password: VALID_PASSWORD })
      .expect(200);
    const otherDeviceToken = refreshTokenFromResponse(otherDevice);

    await request(app).post('/api/v1/auth/refresh').send({ refreshToken: stolen }).expect(200);
    await request(app).post('/api/v1/auth/refresh').send({ refreshToken: stolen }).expect(401);

    // The other device was cut by the cascade. Its next refresh is a casualty of
    // the incident, not a second break-in -- reporting it as reuse would turn one
    // alert into one per device.
    const collateral = await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: otherDeviceToken });

    expect(collateral.status).toBe(401);
    expect(collateral.body.error.message).not.toContain('already been used');
  });
});
