import request from 'supertest';
import { app, VALID_PASSWORD } from './api.js';
import { prisma } from '../../src/lib/prisma.js';
import type { Role } from '../../src/generated/prisma/enums.js';

export interface TestActor {
  id: string;
  email: string;
  accessToken: string;
  refreshToken: string;
}

/**
 * Creates a user at a given role, with a verified email, and signs them in.
 *
 * The role and verification are set directly in the database rather than through
 * the API on purpose: promoting through the API needs a SUPERADMIN to already
 * exist, and the point of these tests is what the guards do, not how the first
 * admin comes to be (that is the set-role script).
 */
export async function createActor(email: string, role: Role = 'USER'): Promise<TestActor> {
  await request(app)
    .post('/api/v1/auth/register')
    .send({ email, password: VALID_PASSWORD })
    .expect(202);

  const user = await prisma.user.update({
    where: { email },
    data: { role, isEmailVerified: true },
  });

  return { ...(await signIn(email)), id: user.id, email };
}

export async function signIn(email: string): Promise<TestActor> {
  const response = await request(app)
    .post('/api/v1/auth/login')
    .send({ email, password: VALID_PASSWORD })
    .expect(200);

  const cookies = response.headers['set-cookie'] as unknown as string[] | undefined;
  const refreshToken =
    cookies
      ?.find((value) => value.startsWith('refresh_token='))
      ?.split(';')[0]
      ?.split('=')[1] ?? '';

  return {
    id: response.body.user.id,
    email: response.body.user.email,
    accessToken: response.body.accessToken,
    refreshToken,
  };
}

export function authHeader(actor: TestActor): [string, string] {
  return ['Authorization', `Bearer ${actor.accessToken}`];
}
