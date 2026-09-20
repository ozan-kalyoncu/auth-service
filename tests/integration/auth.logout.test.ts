import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { app, registerUser, VALID_PASSWORD } from '../helpers/api.js';
import { closeConnections, resetDatabase } from '../helpers/db.js';
import { prisma } from '../../src/lib/prisma.js';
import { hashToken } from '../../src/lib/crypto.js';

beforeEach(resetDatabase);
afterAll(closeConnections);

function refreshTokenFromResponse(response: request.Response): string {
  const cookies = response.headers['set-cookie'] as unknown as string[] | undefined;
  const cookie = cookies?.find((value) => value.startsWith('refresh_token='));

  return cookie?.split(';')[0]?.split('=')[1] ?? '';
}

async function login(email: string): Promise<{ refreshToken: string; accessToken: string }> {
  const response = await request(app)
    .post('/api/v1/auth/login')
    .send({ email, password: VALID_PASSWORD })
    .expect(200);

  return {
    refreshToken: refreshTokenFromResponse(response),
    accessToken: response.body.accessToken,
  };
}

describe('POST /api/v1/auth/logout', () => {
  it('revokes the session and clears the cookie', async () => {
    await registerUser('bye@example.com');
    const { refreshToken } = await login('bye@example.com');

    const response = await request(app)
      .post('/api/v1/auth/logout')
      .set('Cookie', `refresh_token=${refreshToken}`);

    expect(response.status).toBe(204);

    // The browser is told to drop the cookie, with matching attributes -- a
    // mismatch on Path would leave the original cookie in place.
    const cleared = (response.headers['set-cookie'] as unknown as string[])[0];
    expect(cleared).toContain('refresh_token=;');
    expect(cleared).toContain('Path=/api/v1/auth');

    const stored = await prisma.refreshToken.findUnique({
      where: { tokenHash: hashToken(refreshToken) },
    });
    expect(stored?.revokedAt).not.toBeNull();
  });

  it('makes the refresh token unusable', async () => {
    await registerUser('done@example.com');
    const { refreshToken } = await login('done@example.com');

    await request(app).post('/api/v1/auth/logout').send({ refreshToken }).expect(204);

    await request(app).post('/api/v1/auth/refresh').send({ refreshToken }).expect(401);
  });

  it('is idempotent -- logging out twice, or with no token, still succeeds', async () => {
    await registerUser('twice@example.com');
    const { refreshToken } = await login('twice@example.com');

    await request(app).post('/api/v1/auth/logout').send({ refreshToken }).expect(204);
    await request(app).post('/api/v1/auth/logout').send({ refreshToken }).expect(204);
    await request(app).post('/api/v1/auth/logout').send({}).expect(204);
  });

  it('leaves the already-issued access token valid until it expires', async () => {
    await registerUser('stateless@example.com');
    const { refreshToken, accessToken } = await login('stateless@example.com');

    await request(app).post('/api/v1/auth/logout').send({ refreshToken }).expect(204);

    // This is the documented cost of stateless access tokens: logout cuts the
    // ability to get NEW ones, but cannot reach back and invalidate one already
    // handed out. The 15-minute TTL is what bounds the window.
    await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);
  });

  it('does not end other sessions belonging to the same user', async () => {
    await registerUser('multi@example.com');
    const phone = await login('multi@example.com');
    const laptop = await login('multi@example.com');

    await request(app)
      .post('/api/v1/auth/logout')
      .send({ refreshToken: phone.refreshToken })
      .expect(204);

    await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: laptop.refreshToken })
      .expect(200);
  });
});

describe('POST /api/v1/auth/logout-all', () => {
  it('revokes every session for the account', async () => {
    await registerUser('everywhere@example.com');
    const phone = await login('everywhere@example.com');
    const laptop = await login('everywhere@example.com');
    const tablet = await login('everywhere@example.com');

    const response = await request(app)
      .post('/api/v1/auth/logout-all')
      .set('Authorization', `Bearer ${phone.accessToken}`);

    expect(response.status).toBe(200);
    expect(response.body.sessionsRevoked).toBe(3);

    for (const session of [phone, laptop, tablet]) {
      await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: session.refreshToken })
        .expect(401);
    }
  });

  it('requires a valid access token, since it acts on the whole account', async () => {
    await registerUser('guarded@example.com');
    const { refreshToken } = await login('guarded@example.com');

    // A refresh cookie alone is not enough here.
    await request(app)
      .post('/api/v1/auth/logout-all')
      .set('Cookie', `refresh_token=${refreshToken}`)
      .expect(401);

    await request(app).post('/api/v1/auth/logout-all').expect(401);
  });

  it('leaves other users signed in', async () => {
    await registerUser('mine@example.com');
    await registerUser('theirs@example.com');
    const mine = await login('mine@example.com');
    const theirs = await login('theirs@example.com');

    await request(app)
      .post('/api/v1/auth/logout-all')
      .set('Authorization', `Bearer ${mine.accessToken}`)
      .expect(200);

    await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: theirs.refreshToken })
      .expect(200);
  });
});
