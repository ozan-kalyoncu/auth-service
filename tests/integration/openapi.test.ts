import { afterAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import { app } from '../helpers/api.js';
import { closeConnections } from '../helpers/db.js';

afterAll(closeConnections);

describe('GET /api/v1/openapi.json', () => {
  it('serves a document describing every endpoint the service exposes', async () => {
    const response = await request(app).get('/api/v1/openapi.json');

    expect(response.status).toBe(200);
    expect(response.body.openapi).toBe('3.1.0');

    // Kept in step with the routers by hand, so this assertion is what catches a
    // new endpoint shipping without its documentation entry.
    expect(Object.keys(response.body.paths).sort()).toEqual([
      '/auth/login',
      '/auth/logout',
      '/auth/logout-all',
      '/auth/me',
      '/auth/refresh',
      '/auth/register',
      '/auth/resend-verification',
      '/auth/verify-email',
      '/health/live',
      '/health/ready',
    ]);
  });

  it('marks the protected endpoint as requiring a bearer token', async () => {
    const response = await request(app).get('/api/v1/openapi.json');

    expect(response.body.paths['/auth/me'].get.security).toEqual([{ bearerAuth: [] }]);
    expect(response.body.components.securitySchemes.bearerAuth.scheme).toBe('bearer');
  });
});
