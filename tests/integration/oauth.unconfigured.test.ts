import { afterAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import { app } from '../helpers/api.js';
import { closeConnections } from '../helpers/db.js';

/**
 * This file deliberately does NOT set the GitHub credentials, so it sees the
 * deployment as having Google only.
 *
 * OAuth providers are optional and independent: a missing GitHub secret must
 * leave Google and password login entirely unaffected, rather than failing at
 * startup or 500-ing at request time.
 */
afterAll(closeConnections);

describe('a provider without credentials', () => {
  it('is left out of the advertised provider list', async () => {
    const response = await request(app).get('/api/v1/auth/oauth').expect(200);

    expect(response.body.providers).toEqual(['google']);
  });

  it('404s rather than erroring, since this deployment simply does not offer it', async () => {
    const response = await request(app).get('/api/v1/auth/oauth/github');

    expect(response.status).toBe(404);
    expect(response.body.error.code).toBe('NOT_FOUND');
  });

  it('404s on its callback too', async () => {
    await request(app)
      .get('/api/v1/auth/oauth/github/callback')
      .query({ code: 'x', state: 'y' })
      .expect(404);
  });

  it('does not affect the configured provider', async () => {
    await request(app).get('/api/v1/auth/oauth/google').expect(302);
  });

  it('does not affect password login', async () => {
    await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'unaffected@example.com', password: 'correct-horse-battery-staple' })
      .expect(202);
  });
});
