import { afterAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import { createApp } from '../../src/app.js';
import { disconnectPrisma } from '../../src/lib/prisma.js';
import { disconnectRedis } from '../../src/lib/redis.js';

// Supertest is handed the app object directly. It binds an ephemeral port per
// request, so tests never collide on port 3000 and no server cleanup is needed.
const app = createApp();

afterAll(async () => {
  // Open Postgres/Redis handles would keep the Vitest process alive after the
  // last assertion, so they are closed explicitly.
  await Promise.allSettled([disconnectPrisma(), disconnectRedis()]);
});

describe('GET /api/v1/health/live', () => {
  it('reports the process as alive without touching dependencies', async () => {
    const response = await request(app).get('/api/v1/health/live');

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: 'ok' });
  });
});

describe('unknown routes', () => {
  it('returns the standard { error: { code, message } } shape', async () => {
    const response = await request(app).get('/api/v1/does-not-exist');

    expect(response.status).toBe(404);
    expect(response.body.error.code).toBe('NOT_FOUND');
    expect(response.body.error.message).toContain('/api/v1/does-not-exist');
  });
});

describe('security headers', () => {
  it('sets Helmet defaults and hides the framework', async () => {
    const response = await request(app).get('/api/v1/health/live');

    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['x-powered-by']).toBeUndefined();
  });
});
