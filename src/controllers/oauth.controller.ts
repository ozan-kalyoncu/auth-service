import type { Request, Response } from 'express';
import { AppError } from '../lib/app-error.js';
import { logger } from '../lib/logger.js';
import {
  clearOAuthStateCookie,
  setOAuthStateCookie,
  setRefreshTokenCookie,
} from '../lib/cookies.js';
import { buildAuthorizeUrl, exchangeCodeForToken, fetchProfile } from '../lib/oauth/client.js';
import { isProviderConfigured, isProviderName, type ProviderName } from '../lib/oauth/providers.js';
import { consumeState, issueState } from '../services/oauth-state.service.js';
import { findOrCreateUserForProfile, listLinkedProviders } from '../services/oauth.service.js';
import { issueAccessToken, parseDurationToSeconds } from '../services/token.service.js';
import { issueRefreshToken } from '../services/refresh-token.service.js';
import { toPublicUser } from '../services/user.service.js';
import { requireUser } from '../middleware/authenticate.js';
import { OAUTH_STATE_COOKIE } from '../config/constants.js';
import { env } from '../config/env.js';

/**
 * Starts the flow: redirect the browser to the provider.
 *
 * 302 rather than returning the URL as JSON, because this endpoint is meant to
 * be the target of a plain link or form -- the browser has to end up at the
 * provider, and an API client cannot complete this flow anyway.
 */
export async function start(req: Request, res: Response): Promise<void> {
  const provider = requireConfiguredProvider(req.params.provider);

  const state = await issueState(provider);

  // The state goes two places: to the provider in the URL, and into a cookie
  // only this browser holds. The callback requires both to match.
  setOAuthStateCookie(res, state);

  res.redirect(302, buildAuthorizeUrl(provider, state));
}

/**
 * Handles the provider's redirect back to us.
 *
 * Everything before the token exchange is validation of the response itself --
 * the flow has not proven anything yet at that point.
 */
export async function callback(req: Request, res: Response): Promise<void> {
  const provider = requireConfiguredProvider(req.params.provider);

  // The state cookie has served its purpose the moment we read it, and it is
  // cleared whichever way this request goes.
  const stateFromCookie = (req.cookies as Record<string, string> | undefined)?.[
    OAUTH_STATE_COOKIE
  ];
  clearOAuthStateCookie(res);

  const query = req.query as { code?: string; state?: string; error?: string };

  // The user pressed "Cancel" at the provider. Not an error on our side.
  if (query.error) {
    throw AppError.unauthorized('Sign-in was cancelled or denied at the provider');
  }

  const flow = await consumeState(provider, query.state, stateFromCookie);

  if (!flow) {
    // One generic message for every state failure -- missing, mismatched,
    // expired, replayed, wrong provider. Saying which would tell an attacker
    // how close they got.
    logger.warn({ provider }, 'OAuth callback rejected: invalid state');
    throw AppError.unauthorized('Invalid or expired sign-in attempt. Please try again.');
  }

  if (!query.code) {
    throw AppError.badRequest('Provider did not return an authorization code');
  }

  const providerToken = await exchangeCodeForToken(provider, query.code);
  const profile = await fetchProfile(provider, providerToken);

  const { user, outcome } = await findOrCreateUserForProfile(provider, profile);

  // From here on the session is ours: the provider's token was only ever used to
  // learn who this is, and is deliberately not stored. Keeping it would mean
  // holding a live credential to someone's Google account for no reason.
  const refreshToken = await issueRefreshToken(user.id);
  setRefreshTokenCookie(res, refreshToken, parseDurationToSeconds(env.JWT_REFRESH_TTL));

  logger.info({ provider, userId: user.id, outcome }, 'OAuth sign-in complete');

  if (env.OAUTH_SUCCESS_REDIRECT_URL) {
    // Redirect WITHOUT a token in the URL. Query strings and fragments end up in
    // browser history, server logs and Referer headers; the refresh cookie is
    // already set, so the app calls /auth/refresh to get its access token.
    res.redirect(302, env.OAUTH_SUCCESS_REDIRECT_URL);
    return;
  }

  // No frontend configured: return the session as JSON so the flow is usable
  // and demonstrable on its own.
  res.status(200).json({
    user: toPublicUser(user),
    outcome,
    ...issueAccessToken(user),
  });
}

/** Which providers this deployment can actually offer, for a client to render buttons. */
export function listProviders(_req: Request, res: Response): void {
  const providers: ProviderName[] = ['google', 'github'];

  res.status(200).json({
    providers: providers.filter(isProviderConfigured),
  });
}

/** The providers linked to the caller's own account. */
export async function listMyLinkedProviders(req: Request, res: Response): Promise<void> {
  const { id } = requireUser(req);

  res.status(200).json({ providers: await listLinkedProviders(id) });
}

function requireConfiguredProvider(value: string | undefined): ProviderName {
  if (!value || !isProviderName(value)) {
    throw AppError.notFound('Unknown OAuth provider');
  }

  if (!isProviderConfigured(value)) {
    // 404, not 500: from the caller's point of view a provider without
    // credentials simply is not offered by this deployment.
    throw AppError.notFound(`The ${value} provider is not configured on this server`);
  }

  return value;
}
