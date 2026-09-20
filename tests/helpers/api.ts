import request from 'supertest';
import { createApp } from '../../src/app.js';

/**
 * One app instance shared by the tests. Supertest binds an ephemeral port per
 * request, so there is no server to start or stop and no port to collide on.
 */
export const app = createApp();

export const VALID_PASSWORD = 'correct-horse-battery-staple';

/** Registers a user and returns the email used, for tests that need an account to exist. */
export async function registerUser(
  email: string,
  password: string = VALID_PASSWORD,
): Promise<string> {
  await request(app).post('/api/v1/auth/register').send({ email, password }).expect(202);
  return email;
}

/** Registers, logs in, and returns the access token -- the common setup for protected routes. */
export async function registerAndLogin(
  email: string,
  password: string = VALID_PASSWORD,
): Promise<{ accessToken: string; userId: string }> {
  await registerUser(email, password);

  const response = await request(app)
    .post('/api/v1/auth/login')
    .send({ email, password })
    .expect(200);

  return { accessToken: response.body.accessToken, userId: response.body.user.id };
}
