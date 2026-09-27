import { env } from '../../config/env.js';

/**
 * OAuth2 provider definitions.
 *
 * This is a hand-rolled authorization-code client rather than Passport. Passport
 * is built around sessions and serialise/deserialise hooks that a stateless JWT
 * service has no use for, and it hides the exact step -- the code-for-token
 * exchange -- that matters most here. Two providers of straight-line HTTP is
 * less code than the strategy plumbing it would replace.
 */
export type ProviderName = 'google' | 'github';

export interface ProviderConfig {
  name: ProviderName;
  authorizeUrl: string;
  tokenUrl: string;
  /** Scopes we ask for. Request the minimum: every extra scope is data we then have to protect. */
  scopes: string[];
  clientId: string | undefined;
  clientSecret: string | undefined;
}

export const PROVIDERS: Record<ProviderName, ProviderConfig> = {
  google: {
    name: 'google',
    authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    // openid+email is all we need to identify the account. Not `profile` --
    // we store no name or avatar, so asking for them would be collecting data
    // we have no use for.
    scopes: ['openid', 'email'],
    clientId: env.GOOGLE_CLIENT_ID,
    clientSecret: env.GOOGLE_CLIENT_SECRET,
  },
  github: {
    name: 'github',
    authorizeUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    // GitHub hides a user's email from /user unless it is public, so the
    // separate user:email scope is required to read a verified address.
    scopes: ['read:user', 'user:email'],
    clientId: env.GITHUB_CLIENT_ID,
    clientSecret: env.GITHUB_CLIENT_SECRET,
  },
};

export function isProviderName(value: string): value is ProviderName {
  return value === 'google' || value === 'github';
}

/**
 * A provider is usable only if its credentials are present.
 *
 * Checked at request time rather than at startup so the service still boots with
 * one provider configured, or none -- OAuth is optional, and a missing GitHub
 * secret should not stop email/password login from working.
 */
export function isProviderConfigured(name: ProviderName): boolean {
  const provider = PROVIDERS[name];
  return Boolean(provider.clientId && provider.clientSecret);
}

export function callbackUrl(name: ProviderName): string {
  return `${env.OAUTH_CALLBACK_BASE_URL}/api/v1/auth/oauth/${name}/callback`;
}
