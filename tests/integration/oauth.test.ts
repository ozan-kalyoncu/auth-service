import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';

// Must be set before the app (and therefore config/env) is imported, so both
// providers count as configured in this file.
process.env.GITHUB_CLIENT_ID = 'test-github-client-id';
process.env.GITHUB_CLIENT_SECRET = 'test-github-client-secret';

/**
 * The two functions that talk to Google/GitHub over the network are replaced;
 * everything else -- state handling, linking rules, session issuing -- runs for
 * real. That keeps the tests offline and deterministic while still exercising
 * the logic this milestone is actually about.
 */
const { providerProfile } = vi.hoisted(() => ({
  providerProfile: {
    current: { providerUserId: 'google-1', email: 'oauth@example.com', emailVerified: true },
  },
}));

vi.mock('../../src/lib/oauth/client.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/lib/oauth/client.js')>();

  return {
    ...actual,
    exchangeCodeForToken: async () => 'provider-access-token',
    fetchProfile: async () => providerProfile.current,
  };
});

const { app } = await import('../helpers/api.js');
const { resetDatabase, closeConnections } = await import('../helpers/db.js');
const { prisma } = await import('../../src/lib/prisma.js');

beforeEach(async () => {
  await resetDatabase();
  providerProfile.current = {
    providerUserId: 'google-1',
    email: 'oauth@example.com',
    emailVerified: true,
  };
});

afterAll(closeConnections);

interface StartedFlow {
  state: string;
  cookie: string;
}

/** Runs the redirect step and captures the state from both the URL and the cookie. */
async function startFlow(provider = 'google'): Promise<StartedFlow> {
  const response = await request(app).get(`/api/v1/auth/oauth/${provider}`).expect(302);

  const location = new URL(response.headers.location as string);
  const cookies = response.headers['set-cookie'] as unknown as string[];
  const cookie = cookies.find((value) => value.startsWith('oauth_state='))?.split(';')[0] ?? '';

  return { state: location.searchParams.get('state') ?? '', cookie };
}

function completeFlow(flow: StartedFlow, provider = 'google'): request.Test {
  return request(app)
    .get(`/api/v1/auth/oauth/${provider}/callback`)
    .query({ code: 'provider-auth-code', state: flow.state })
    .set('Cookie', flow.cookie);
}

describe('GET /api/v1/auth/oauth', () => {
  it('lists only the providers this deployment has credentials for', async () => {
    const response = await request(app).get('/api/v1/auth/oauth').expect(200);

    expect(response.body.providers).toEqual(['google', 'github']);
  });
});

describe('starting a flow', () => {
  it('redirects to the provider with the parameters it expects', async () => {
    const response = await request(app).get('/api/v1/auth/oauth/google').expect(302);

    const location = new URL(response.headers.location as string);

    expect(location.origin + location.pathname).toBe(
      'https://accounts.google.com/o/oauth2/v2/auth',
    );
    expect(location.searchParams.get('client_id')).toBe('test-google-client-id');
    expect(location.searchParams.get('response_type')).toBe('code');
    expect(location.searchParams.get('redirect_uri')).toBe(
      'http://localhost:3000/api/v1/auth/oauth/google/callback',
    );
    expect(location.searchParams.get('scope')).toBe('openid email');
    expect(location.searchParams.get('state')).toBeTruthy();
  });

  it('binds the state to this browser with a Lax, httpOnly cookie', async () => {
    const response = await request(app).get('/api/v1/auth/oauth/google').expect(302);

    const cookie = (response.headers['set-cookie'] as unknown as string[])[0] as string;

    expect(cookie).toContain('HttpOnly');
    // Lax, not Strict: the user returns via a cross-site top-level navigation
    // from the provider, and a Strict cookie would be withheld on exactly that.
    expect(cookie).toContain('SameSite=Lax');
    expect(cookie).toContain('Path=/api/v1/auth/oauth');
  });

  it('404s for an unknown provider', async () => {
    await request(app).get('/api/v1/auth/oauth/facebook').expect(404);
  });
});

describe('state validation on the callback', () => {
  it('rejects a callback with no state at all', async () => {
    const response = await request(app)
      .get('/api/v1/auth/oauth/google/callback')
      .query({ code: 'x' });

    expect(response.status).toBe(401);
    await expect(prisma.user.count()).resolves.toBe(0);
  });

  it('rejects a state that does not match the cookie', async () => {
    const flow = await startFlow();

    // An attacker supplying their own state in the URL, without the matching
    // cookie, is the login-CSRF case this parameter exists to stop.
    const response = await request(app)
      .get('/api/v1/auth/oauth/google/callback')
      .query({ code: 'x', state: 'attacker-supplied-state' })
      .set('Cookie', flow.cookie);

    expect(response.status).toBe(401);
  });

  it('rejects a state presented without its cookie', async () => {
    const flow = await startFlow();

    await request(app)
      .get('/api/v1/auth/oauth/google/callback')
      .query({ code: 'x', state: flow.state })
      .expect(401);
  });

  it('rejects a replayed callback -- state is single-use', async () => {
    const flow = await startFlow();

    await completeFlow(flow).expect(200);
    await completeFlow(flow).expect(401);

    // The replay must not have produced a second account.
    await expect(prisma.user.count()).resolves.toBe(1);
  });

  it('refuses a state minted for one provider at the other provider\'s callback', async () => {
    const flow = await startFlow('google');

    await request(app)
      .get('/api/v1/auth/oauth/github/callback')
      .query({ code: 'x', state: flow.state })
      .set('Cookie', flow.cookie)
      .expect(401);
  });

  it('reports a cancelled sign-in without creating anything', async () => {
    const flow = await startFlow();

    const response = await request(app)
      .get('/api/v1/auth/oauth/google/callback')
      .query({ error: 'access_denied', state: flow.state })
      .set('Cookie', flow.cookie);

    expect(response.status).toBe(401);
    await expect(prisma.user.count()).resolves.toBe(0);
  });
});

describe('creating an account from a provider', () => {
  it('creates a user with no password and a verified email', async () => {
    const response = await completeFlow(await startFlow()).expect(200);

    expect(response.body.outcome).toBe('created');
    expect(response.body.accessToken).toBeTruthy();
    expect(response.body.user.email).toBe('oauth@example.com');

    const user = await prisma.user.findUnique({
      where: { email: 'oauth@example.com' },
      include: { oauthAccounts: true },
    });

    // Null, not a random placeholder: this account genuinely has no password,
    // which is exactly what the nullable column is for.
    expect(user?.passwordHash).toBeNull();
    expect(user?.isEmailVerified).toBe(true);
    expect(user?.oauthAccounts).toHaveLength(1);
    expect(user?.oauthAccounts[0]?.provider).toBe('google');
    expect(user?.oauthAccounts[0]?.providerUserId).toBe('google-1');
  });

  it('signs the same identity back in without duplicating the account', async () => {
    await completeFlow(await startFlow()).expect(200);
    const second = await completeFlow(await startFlow()).expect(200);

    expect(second.body.outcome).toBe('signed-in');
    await expect(prisma.user.count()).resolves.toBe(1);
    await expect(prisma.oAuthAccount.count()).resolves.toBe(1);
  });

  it('follows the provider when it says the email is unverified', async () => {
    providerProfile.current = {
      providerUserId: 'google-unverified',
      email: 'unverified@example.com',
      emailVerified: false,
    };

    await completeFlow(await startFlow()).expect(200);

    const user = await prisma.user.findUnique({ where: { email: 'unverified@example.com' } });
    expect(user?.isEmailVerified).toBe(false);
  });

  it('issues a refresh cookie that works against /auth/refresh', async () => {
    const response = await completeFlow(await startFlow()).expect(200);

    const cookies = response.headers['set-cookie'] as unknown as string[];
    const refreshCookie = cookies.find((value) => value.startsWith('refresh_token='));

    expect(refreshCookie).toBeDefined();

    await request(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', refreshCookie?.split(';')[0] as string)
      .expect(200);
  });

  it('issues an access token that works on a protected route', async () => {
    const response = await completeFlow(await startFlow()).expect(200);

    const me = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${response.body.accessToken}`)
      .expect(200);

    expect(me.body.user.email).toBe('oauth@example.com');
  });
});

describe('account linking', () => {
  async function registerPasswordUser(email: string): Promise<string> {
    await request(app)
      .post('/api/v1/auth/register')
      .send({ email, password: 'correct-horse-battery-staple' })
      .expect(202);

    const user = await prisma.user.findUnique({ where: { email } });
    return user?.id as string;
  }

  it('links a provider identity to an existing password account', async () => {
    const userId = await registerPasswordUser('both@example.com');
    providerProfile.current = {
      providerUserId: 'google-both',
      email: 'both@example.com',
      emailVerified: true,
    };

    const response = await completeFlow(await startFlow()).expect(200);

    expect(response.body.outcome).toBe('linked');
    expect(response.body.user.id).toBe(userId);

    // One account, both sign-in methods.
    await expect(prisma.user.count()).resolves.toBe(1);

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { oauthAccounts: true },
    });
    expect(user?.oauthAccounts).toHaveLength(1);
    // Linking must not disturb the existing password.
    expect(user?.passwordHash).toMatch(/^\$argon2id\$/);
  });

  it('still lets the user sign in with their password after linking', async () => {
    await registerPasswordUser('both@example.com');
    providerProfile.current = {
      providerUserId: 'google-both',
      email: 'both@example.com',
      emailVerified: true,
    };
    await completeFlow(await startFlow()).expect(200);

    await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'both@example.com', password: 'correct-horse-battery-staple' })
      .expect(200);
  });

  it('REFUSES to link on an unverified provider email', async () => {
    const userId = await registerPasswordUser('victim@example.com');

    // The pre-account-takeover attack: an attacker registers victim@example.com
    // at a provider that does not verify addresses, then signs in here hoping to
    // be handed the victim's account.
    providerProfile.current = {
      providerUserId: 'attacker-account',
      email: 'victim@example.com',
      emailVerified: false,
    };

    const response = await completeFlow(await startFlow());

    expect(response.status).toBe(403);

    // No link created, and no second account either.
    const links = await prisma.oAuthAccount.findMany({ where: { userId } });
    expect(links).toHaveLength(0);
    await expect(prisma.user.count()).resolves.toBe(1);
  });

  it('matches emails case-insensitively when linking', async () => {
    const userId = await registerPasswordUser('mixed@example.com');
    providerProfile.current = {
      providerUserId: 'google-mixed',
      email: 'Mixed@Example.COM',
      emailVerified: true,
    };

    const response = await completeFlow(await startFlow()).expect(200);

    expect(response.body.outcome).toBe('linked');
    expect(response.body.user.id).toBe(userId);
    await expect(prisma.user.count()).resolves.toBe(1);
  });

  it('links a second provider to the same account', async () => {
    providerProfile.current = {
      providerUserId: 'google-multi',
      email: 'multi@example.com',
      emailVerified: true,
    };
    const first = await completeFlow(await startFlow()).expect(200);

    providerProfile.current = {
      providerUserId: 'github-multi',
      email: 'multi@example.com',
      emailVerified: true,
    };
    const second = await completeFlow(await startFlow('github'), 'github').expect(200);

    expect(first.body.outcome).toBe('created');
    expect(second.body.outcome).toBe('linked');
    expect(second.body.user.id).toBe(first.body.user.id);

    await expect(prisma.user.count()).resolves.toBe(1);
    await expect(prisma.oAuthAccount.count()).resolves.toBe(2);
  });

  it('keeps identities apart when the same provider id belongs to different providers', async () => {
    providerProfile.current = {
      providerUserId: 'shared-id-123',
      email: 'a@example.com',
      emailVerified: true,
    };
    await completeFlow(await startFlow()).expect(200);

    providerProfile.current = {
      providerUserId: 'shared-id-123',
      email: 'b@example.com',
      emailVerified: true,
    };
    await completeFlow(await startFlow('github'), 'github').expect(200);

    // The unique constraint is on (provider, providerUserId), so a GitHub user
    // who happens to share a numeric id with a Google user is a different person.
    await expect(prisma.user.count()).resolves.toBe(2);
  });
});

describe('GET /api/v1/auth/oauth/linked', () => {
  it('lists the providers linked to the caller', async () => {
    const response = await completeFlow(await startFlow()).expect(200);

    const linked = await request(app)
      .get('/api/v1/auth/oauth/linked')
      .set('Authorization', `Bearer ${response.body.accessToken}`)
      .expect(200);

    expect(linked.body.providers).toEqual(['google']);
  });

  it('requires authentication', async () => {
    await request(app).get('/api/v1/auth/oauth/linked').expect(401);
  });
});
