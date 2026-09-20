import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { app } from '../helpers/api.js';
import { closeConnections, resetDatabase } from '../helpers/db.js';
import { authHeader, createActor } from '../helpers/roles.js';
import { prisma } from '../../src/lib/prisma.js';

beforeEach(resetDatabase);
afterAll(closeConnections);

describe('guard order: authentication before authorization', () => {
  it('returns 401 when nobody is authenticated, not 403', async () => {
    const response = await request(app).get('/api/v1/users');

    // "I do not know who you are" -- retrying with credentials can fix this.
    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('UNAUTHORIZED');
  });

  it('returns 403 when the caller is known but lacks the permission', async () => {
    const user = await createActor('plain@example.com', 'USER');

    const response = await request(app).get('/api/v1/users').set(...authHeader(user));

    // "I know who you are, and the answer is still no" -- retrying cannot help,
    // which is why this must not be a 401.
    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('FORBIDDEN');
  });

  it('refuses a privileged route to an unverified account', async () => {
    const admin = await createActor('unverified-admin@example.com', 'ADMIN');
    await prisma.user.update({
      where: { id: admin.id },
      data: { isEmailVerified: false },
    });

    const response = await request(app).get('/api/v1/users').set(...authHeader(admin));

    expect(response.status).toBe(403);
    expect(response.body.error.message).toContain('verified');
  });

  it('rejects an unauthorized caller before telling them the input was malformed', async () => {
    const user = await createActor('nosy@example.com', 'USER');

    // A 400 here would confirm the endpoint's expected shape to someone with no
    // business calling it at all.
    const response = await request(app)
      .get('/api/v1/users?limit=not-a-number')
      .set(...authHeader(user));

    expect(response.status).toBe(403);
  });
});

describe('GET /api/v1/users', () => {
  it('allows an admin and paginates', async () => {
    const admin = await createActor('admin@example.com', 'ADMIN');
    await createActor('one@example.com');
    await createActor('two@example.com');

    const response = await request(app)
      .get('/api/v1/users?limit=2&offset=0')
      .set(...authHeader(admin));

    expect(response.status).toBe(200);
    expect(response.body.users).toHaveLength(2);
    expect(response.body.total).toBe(3);
    expect(response.body.limit).toBe(2);

    // Never leak hashes through a list endpoint.
    expect(JSON.stringify(response.body)).not.toContain('argon2');
  });

  it('applies sane defaults and caps the page size', async () => {
    const admin = await createActor('capper@example.com', 'ADMIN');

    const defaults = await request(app).get('/api/v1/users').set(...authHeader(admin));
    expect(defaults.body.limit).toBe(20);
    expect(defaults.body.offset).toBe(0);

    // An uncapped limit is a one-request denial of service.
    const tooBig = await request(app)
      .get('/api/v1/users?limit=100000')
      .set(...authHeader(admin));
    expect(tooBig.status).toBe(400);
    expect(tooBig.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('allows a superadmin, since permissions are inherited', async () => {
    const superadmin = await createActor('super@example.com', 'SUPERADMIN');

    await request(app).get('/api/v1/users').set(...authHeader(superadmin)).expect(200);
  });
});

describe('GET /api/v1/users/:id', () => {
  it('lets any user read their own record without a permission', async () => {
    const user = await createActor('self@example.com', 'USER');

    const response = await request(app)
      .get(`/api/v1/users/${user.id}`)
      .set(...authHeader(user));

    expect(response.status).toBe(200);
    expect(response.body.user.email).toBe('self@example.com');
  });

  it('refuses a plain user reading someone else', async () => {
    const user = await createActor('nosy@example.com', 'USER');
    const other = await createActor('other@example.com', 'USER');

    await request(app)
      .get(`/api/v1/users/${other.id}`)
      .set(...authHeader(user))
      .expect(403);
  });

  it('gives the same 403 for a non-existent id, so ids cannot be probed', async () => {
    const user = await createActor('prober@example.com', 'USER');

    const real = await createActor('exists@example.com', 'USER');
    const existing = await request(app)
      .get(`/api/v1/users/${real.id}`)
      .set(...authHeader(user));

    const madeUp = await request(app)
      .get('/api/v1/users/clx000000000000000000000')
      .set(...authHeader(user));

    // Identical responses: an unprivileged caller cannot use the difference
    // between 403 and 404 to discover which ids exist.
    expect(madeUp.status).toBe(existing.status);
    expect(madeUp.body).toEqual(existing.body);
  });

  it('lets an admin read anyone, and 404s only for privileged callers', async () => {
    const admin = await createActor('reader@example.com', 'ADMIN');
    const target = await createActor('target@example.com', 'USER');

    await request(app)
      .get(`/api/v1/users/${target.id}`)
      .set(...authHeader(admin))
      .expect(200);

    await request(app)
      .get('/api/v1/users/clx000000000000000000000')
      .set(...authHeader(admin))
      .expect(404);
  });
});

describe('PATCH /api/v1/users/:id/role', () => {
  it('lets a superadmin promote a user', async () => {
    const superadmin = await createActor('boss@example.com', 'SUPERADMIN');
    const target = await createActor('promoted@example.com', 'USER');

    const response = await request(app)
      .patch(`/api/v1/users/${target.id}/role`)
      .set(...authHeader(superadmin))
      .send({ role: 'ADMIN' });

    expect(response.status).toBe(200);
    expect(response.body.user.role).toBe('ADMIN');

    const stored = await prisma.user.findUnique({ where: { id: target.id } });
    expect(stored?.role).toBe('ADMIN');
  });

  it('refuses an admin — managing roles is a superadmin capability', async () => {
    const admin = await createActor('admin@example.com', 'ADMIN');
    const target = await createActor('victim@example.com', 'USER');

    const response = await request(app)
      .patch(`/api/v1/users/${target.id}/role`)
      .set(...authHeader(admin))
      .send({ role: 'SUPERADMIN' });

    expect(response.status).toBe(403);
    expect(response.body.error.message).toContain('users:manage-roles');

    const stored = await prisma.user.findUnique({ where: { id: target.id } });
    expect(stored?.role).toBe('USER');
  });

  it('revokes the target\'s sessions so the old role cannot be renewed', async () => {
    const superadmin = await createActor('boss@example.com', 'SUPERADMIN');
    const target = await createActor('demoted@example.com', 'ADMIN');

    // Confirm the target really does have admin access before the change.
    await request(app).get('/api/v1/users').set(...authHeader(target)).expect(200);

    await request(app)
      .patch(`/api/v1/users/${target.id}/role`)
      .set(...authHeader(superadmin))
      .send({ role: 'USER' })
      .expect(200);

    // Their refresh token is dead, so the demoted role cannot outlive the access
    // token they are currently holding.
    await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: target.refreshToken })
      .expect(401);

    // Documented consequence of stateless tokens: the access token already in
    // their hands still carries ADMIN until it expires. The revocation above is
    // what bounds that window to the access TTL instead of the refresh TTL.
    await request(app).get('/api/v1/users').set(...authHeader(target)).expect(200);

    // Signing in again reflects the new role immediately.
    const after = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'demoted@example.com', password: 'correct-horse-battery-staple' })
      .expect(200);

    await request(app)
      .get('/api/v1/users')
      .set('Authorization', `Bearer ${after.body.accessToken}`)
      .expect(403);
  });

  it('refuses self-demotion, which is how an org locks itself out', async () => {
    const superadmin = await createActor('lonely@example.com', 'SUPERADMIN');

    const response = await request(app)
      .patch(`/api/v1/users/${superadmin.id}/role`)
      .set(...authHeader(superadmin))
      .send({ role: 'USER' });

    expect(response.status).toBe(403);
    expect(response.body.error.message).toContain('your own role');

    const stored = await prisma.user.findUnique({ where: { id: superadmin.id } });
    expect(stored?.role).toBe('SUPERADMIN');
  });

  it('rejects a role that is not in the enum', async () => {
    const superadmin = await createActor('boss@example.com', 'SUPERADMIN');
    const target = await createActor('target@example.com', 'USER');

    const response = await request(app)
      .patch(`/api/v1/users/${target.id}/role`)
      .set(...authHeader(superadmin))
      .send({ role: 'GOD_MODE' });

    // A clear 400 rather than a 500 from the database rejecting the enum value.
    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('404s for a user that does not exist', async () => {
    const superadmin = await createActor('boss@example.com', 'SUPERADMIN');

    await request(app)
      .patch('/api/v1/users/clx000000000000000000000/role')
      .set(...authHeader(superadmin))
      .send({ role: 'ADMIN' })
      .expect(404);
  });
});

describe('DELETE /api/v1/users/:id', () => {
  it('lets a superadmin delete a user and takes their sessions with them', async () => {
    const superadmin = await createActor('boss@example.com', 'SUPERADMIN');
    const target = await createActor('doomed@example.com', 'USER');

    await request(app)
      .delete(`/api/v1/users/${target.id}`)
      .set(...authHeader(superadmin))
      .expect(204);

    expect(await prisma.user.findUnique({ where: { id: target.id } })).toBeNull();

    // Cascade: no orphaned refresh tokens left behind.
    expect(await prisma.refreshToken.findMany({ where: { userId: target.id } })).toHaveLength(0);

    await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: target.refreshToken })
      .expect(401);
  });

  it('keeps the login audit trail after the account is gone', async () => {
    const superadmin = await createActor('boss@example.com', 'SUPERADMIN');
    const target = await createActor('audited@example.com', 'USER');

    await request(app)
      .delete(`/api/v1/users/${target.id}`)
      .set(...authHeader(superadmin))
      .expect(204);

    // SetNull rather than Cascade: who tried to log in, and when, outlives the
    // account it belonged to.
    const attempts = await prisma.loginAttempt.findMany();
    expect(attempts.length).toBeGreaterThan(0);
    expect(attempts.every((attempt) => attempt.userId !== target.id)).toBe(true);
  });

  it('refuses an admin, who may read users but not delete them', async () => {
    const admin = await createActor('admin@example.com', 'ADMIN');
    const target = await createActor('safe@example.com', 'USER');

    await request(app)
      .delete(`/api/v1/users/${target.id}`)
      .set(...authHeader(admin))
      .expect(403);

    expect(await prisma.user.findUnique({ where: { id: target.id } })).not.toBeNull();
  });

  it('refuses self-deletion', async () => {
    const superadmin = await createActor('boss@example.com', 'SUPERADMIN');

    const response = await request(app)
      .delete(`/api/v1/users/${superadmin.id}`)
      .set(...authHeader(superadmin));

    expect(response.status).toBe(403);
    expect(await prisma.user.findUnique({ where: { id: superadmin.id } })).not.toBeNull();
  });
});

describe('GET /api/v1/auth/me', () => {
  it('reports the permissions that go with the caller\'s role', async () => {
    const user = await createActor('u@example.com', 'USER');
    const admin = await createActor('a@example.com', 'ADMIN');
    const superadmin = await createActor('s@example.com', 'SUPERADMIN');

    const userResponse = await request(app).get('/api/v1/auth/me').set(...authHeader(user));
    const adminResponse = await request(app).get('/api/v1/auth/me').set(...authHeader(admin));
    const superResponse = await request(app).get('/api/v1/auth/me').set(...authHeader(superadmin));

    expect(userResponse.body.permissions).toEqual([]);
    expect(adminResponse.body.permissions).toEqual(['users:read']);
    expect(superResponse.body.permissions).toEqual([
      'users:read',
      'users:manage-roles',
      'users:delete',
    ]);
  });
});
