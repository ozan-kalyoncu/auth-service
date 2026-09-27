import { AppError } from '../app-error.js';
import { logger } from '../logger.js';
import { callbackUrl, PROVIDERS, type ProviderName } from './providers.js';

/**
 * The provider-facing half of the OAuth2 authorization-code flow.
 *
 * The flow in four steps:
 *   1. we redirect the user to the provider with our client_id and a `state`
 *   2. they sign in there and approve; the provider redirects back with a `code`
 *   3. we exchange that code for an access token -- server to server, using our
 *      client_secret, so the token never passes through the browser
 *   4. we call the provider's API with that token to learn who they are
 *
 * Step 3 is the reason the code is short-lived and single-use: the code travels
 * through the user's browser where it can be observed, but it is worthless
 * without the secret that only our server holds.
 */

/** What we actually need from a provider, normalised across both. */
export interface OAuthProfile {
  providerUserId: string;
  email: string;
  /**
   * Whether the PROVIDER has verified this address.
   *
   * Load-bearing for account linking: an unverified address proves nothing about
   * who controls the mailbox, and linking on one would let an attacker take over
   * an existing account by signing up elsewhere with its email.
   */
  emailVerified: boolean;
}

export function buildAuthorizeUrl(provider: ProviderName, state: string): string {
  const config = PROVIDERS[provider];
  const url = new URL(config.authorizeUrl);

  url.searchParams.set('client_id', config.clientId ?? '');
  url.searchParams.set('redirect_uri', callbackUrl(provider));
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', config.scopes.join(' '));

  // Opaque value echoed back to us on the callback. It is what ties the response
  // to the request we started -- see oauth-state.service for why that matters.
  url.searchParams.set('state', state);

  return url.toString();
}

/**
 * Step 3: trade the one-time code for an access token.
 *
 * Note this is a direct server-to-server POST, not a redirect. The client_secret
 * is in the body, which is precisely why this cannot happen in the browser.
 */
export async function exchangeCodeForToken(
  provider: ProviderName,
  code: string,
): Promise<string> {
  const config = PROVIDERS[provider];

  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      // GitHub returns form-encoded by default; both honour this and reply JSON.
      Accept: 'application/json',
    },
    body: new URLSearchParams({
      client_id: config.clientId ?? '',
      client_secret: config.clientSecret ?? '',
      code,
      redirect_uri: callbackUrl(provider),
      grant_type: 'authorization_code',
    }),
  });

  if (!response.ok) {
    // Deliberately vague to the client. The provider's error text can name our
    // client_id or the exact misconfiguration, which is for our logs, not theirs.
    logger.error(
      { provider, status: response.status },
      'OAuth token exchange failed',
    );
    throw AppError.unauthorized('Could not complete sign-in with that provider');
  }

  const payload = (await response.json()) as { access_token?: string; error?: string };

  if (!payload.access_token) {
    logger.error({ provider, error: payload.error }, 'OAuth token exchange returned no token');
    throw AppError.unauthorized('Could not complete sign-in with that provider');
  }

  return payload.access_token;
}

/** Step 4: ask the provider who this token belongs to. */
export async function fetchProfile(
  provider: ProviderName,
  accessToken: string,
): Promise<OAuthProfile> {
  return provider === 'google'
    ? fetchGoogleProfile(accessToken)
    : fetchGithubProfile(accessToken);
}

async function fetchGoogleProfile(accessToken: string): Promise<OAuthProfile> {
  const response = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    throw AppError.unauthorized('Could not read your Google profile');
  }

  const profile = (await response.json()) as {
    sub?: string;
    email?: string;
    email_verified?: boolean;
  };

  if (!profile.sub || !profile.email) {
    throw AppError.unauthorized('Google did not return an email address');
  }

  return {
    // `sub` is Google's stable per-user id. Never key the link on email: people
    // change their email address, and reusing one as an identifier means the
    // next owner of that address inherits the account.
    providerUserId: profile.sub,
    email: profile.email,
    emailVerified: profile.email_verified === true,
  };
}

async function fetchGithubProfile(accessToken: string): Promise<OAuthProfile> {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    Accept: 'application/vnd.github+json',
    'User-Agent': 'auth-service',
  };

  const userResponse = await fetch('https://api.github.com/user', { headers });

  if (!userResponse.ok) {
    throw AppError.unauthorized('Could not read your GitHub profile');
  }

  const user = (await userResponse.json()) as { id?: number };

  if (!user.id) {
    throw AppError.unauthorized('GitHub did not return a user id');
  }

  // /user omits the email unless the account made it public, so the verified
  // address has to come from the dedicated endpoint.
  const emailsResponse = await fetch('https://api.github.com/user/emails', { headers });

  if (!emailsResponse.ok) {
    throw AppError.unauthorized('Could not read your GitHub email addresses');
  }

  const emails = (await emailsResponse.json()) as {
    email: string;
    primary: boolean;
    verified: boolean;
  }[];

  // Prefer the primary verified address; fall back to any verified one. An
  // unverified address is never used -- see the linking rules in oauth.service.
  const chosen = emails.find((e) => e.primary && e.verified) ?? emails.find((e) => e.verified);

  if (!chosen) {
    throw AppError.unauthorized(
      'Your GitHub account has no verified email address. Verify one with GitHub and try again.',
    );
  }

  return {
    providerUserId: String(user.id),
    email: chosen.email,
    emailVerified: true,
  };
}
