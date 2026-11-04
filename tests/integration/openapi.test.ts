import { afterAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import { app } from '../helpers/api.js';
import { closeConnections } from '../helpers/db.js';
import { listRoutes } from '../helpers/routes.js';

afterAll(closeConnections);

// Routes that serve the documentation itself rather than the API it describes.
const META_ROUTES = new Set(['GET /api/v1/openapi.json']);

describe('GET /api/v1/openapi.json', () => {
  it('documents exactly the routes the app serves, method by method', async () => {
    const response = await request(app).get('/api/v1/openapi.json');

    expect(response.status).toBe(200);
    expect(response.body.openapi).toBe('3.1.0');

    // The spec is hand-written, so drift is its main failure mode. Comparing it
    // against the live router -- not against a list someone has to remember to
    // update -- catches both an endpoint shipped without docs and docs left
    // behind for an endpoint that was removed.
    const documented = Object.entries(response.body.paths as Record<string, object>)
      .flatMap(([path, operations]) =>
        Object.keys(operations).map((method) => `${method.toUpperCase()} /api/v1${path}`),
      )
      .sort();

    const served = listRoutes(app).filter((route) => !META_ROUTES.has(route));

    expect(documented).toEqual(served);
  });

  it('marks the protected endpoint as requiring a bearer token', async () => {
    const response = await request(app).get('/api/v1/openapi.json');

    expect(response.body.paths['/auth/me'].get.security).toEqual([{ bearerAuth: [] }]);
    expect(response.body.components.securitySchemes.bearerAuth.scheme).toBe('bearer');
  });
});

describe('GET /api/v1/docs', () => {
  it('serves Swagger UI pointed at the JSON document', async () => {
    const page = await request(app).get('/api/v1/docs/');

    expect(page.status).toBe(200);
    expect(page.headers['content-type']).toMatch(/text\/html/);
    expect(page.text).toContain('Auth Service API');

    // The UI's init script is a separate same-origin file, so Helmet's CSP needs
    // no 'unsafe-inline' for scripts. It should fetch the spec, not embed it.
    const init = await request(app).get('/api/v1/docs/swagger-ui-init.js');
    expect(init.status).toBe(200);
    expect(init.text).toContain('/api/v1/openapi.json');
    expect(page.headers['content-security-policy']).not.toMatch(/script-src[^;]*unsafe-inline/);
  });
});
