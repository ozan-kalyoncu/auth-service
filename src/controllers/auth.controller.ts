import type { Request, Response } from 'express';
import * as authService from '../services/auth.service.js';
import type { LoginResult } from '../services/auth.service.js';
import { findUserById } from '../services/user.service.js';
import { toPublicUser } from '../services/user.service.js';
import { parseDurationToSeconds } from '../services/token.service.js';
import { requireUser } from '../middleware/authenticate.js';
import { AppError } from '../lib/app-error.js';
import { clearRefreshTokenCookie, setRefreshTokenCookie } from '../lib/cookies.js';
import { REFRESH_TOKEN_COOKIE } from '../config/constants.js';
import { env } from '../config/env.js';
import type { LoginInput, RegisterInput } from '../validators/auth.validators.js';

/**
 * Controllers translate HTTP into service calls and back. They hold no business
 * logic and no SQL -- which is what lets the services be tested without faking a
 * request, and keeps each handler small enough to read at a glance.
 *
 * Validation already ran in middleware, so req.body here is parsed and trusted.
 */

export async function register(req: Request, res: Response): Promise<void> {
  const { email, password } = req.body as RegisterInput;

  await authService.register(email, password);

  // 202 Accepted, not 201 Created, and the same response either way -- because
  // this endpoint deliberately does not reveal whether an account was created or
  // already existed (see auth.service.register).
  res.status(202).json({
    message: 'If that email address is available, a verification link has been sent to it.',
  });
}

export async function login(req: Request, res: Response): Promise<void> {
  const { email, password } = req.body as LoginInput;

  // req.ip respects the `trust proxy` setting configured in app.ts, so behind a
  // load balancer this is the real client address rather than the proxy's.
  const result = await authService.login(email, password, req.ip ?? 'unknown');

  sendSession(res, result);
}

/**
 * Rotates the refresh token and returns a new access token.
 *
 * This is the endpoint a client calls when its access token is about to expire,
 * so the user stays signed in for the refresh token's lifetime without ever
 * re-entering a password.
 */
export async function refresh(req: Request, res: Response): Promise<void> {
  const token = readRefreshToken(req);

  if (!token) {
    throw AppError.unauthorized('No refresh token provided');
  }

  const result = await authService.refreshSession(token);

  sendSession(res, result);
}

export async function logout(req: Request, res: Response): Promise<void> {
  await authService.logout(readRefreshToken(req));

  // Clearing the cookie matters even when no token was found: it removes a stale
  // cookie from the browser rather than leaving it to be sent on every refresh.
  clearRefreshTokenCookie(res);

  // 204: the client asked us to forget a session, and there is nothing to return.
  res.status(204).send();
}

/** Signs out every device. Requires an access token, since it acts on the whole account. */
export async function logoutAll(req: Request, res: Response): Promise<void> {
  const { id } = requireUser(req);

  const sessionsRevoked = await authService.logoutAllSessions(id);

  clearRefreshTokenCookie(res);
  res.status(200).json({ sessionsRevoked });
}

/**
 * Reads the refresh token from the cookie, falling back to the request body.
 *
 * The cookie is the path browsers use, and the one that keeps the token out of
 * reach of JavaScript. The body fallback exists because this service is meant to
 * be called by other services and by curl/Postman, where there is no cookie jar
 * and no XSS to defend against.
 */
function readRefreshToken(req: Request): string | undefined {
  const fromCookie = (req.cookies as Record<string, string> | undefined)?.[REFRESH_TOKEN_COOKIE];

  if (fromCookie) return fromCookie;

  const body = req.body as { refreshToken?: unknown } | undefined;

  return typeof body?.refreshToken === 'string' && body.refreshToken.length > 0
    ? body.refreshToken
    : undefined;
}

/**
 * Writes a freshly issued session to the response.
 *
 * The refresh token goes ONLY into the httpOnly cookie -- never into the JSON
 * body, which client-side script can read. Shared by login and refresh so the
 * two cannot drift apart on this.
 */
function sendSession(res: Response, result: LoginResult): void {
  setRefreshTokenCookie(res, result.refreshToken, refreshTokenMaxAgeSeconds());

  res.status(200).json({
    user: result.user,
    ...result.tokens,
  });
}

function refreshTokenMaxAgeSeconds(): number {
  return parseDurationToSeconds(env.JWT_REFRESH_TTL);
}

export async function verifyEmail(req: Request, res: Response): Promise<void> {
  const { token } = req.query as { token: string };

  await authService.verifyEmail(token);

  res.status(200).json({ message: 'Email address verified. You can now sign in.' });
}

export async function resendVerification(req: Request, res: Response): Promise<void> {
  const { email } = req.body as { email: string };

  await authService.resendVerificationEmail(email);

  // Same generic response whether or not the address exists or is already
  // verified -- this endpoint must not become an enumeration oracle either.
  res.status(202).json({
    message: 'If that account exists and is unverified, a new verification link has been sent.',
  });
}

/**
 * Returns the authenticated user. This is the endpoint that proves the whole
 * chain works: a token issued at login is accepted by the authenticate guard and
 * resolves to a real account.
 */
export async function getCurrentUser(req: Request, res: Response): Promise<void> {
  const { id } = requireUser(req);

  const user = await findUserById(id);

  if (!user) {
    // Valid signature, but the account has since been deleted -- the known cost
    // of stateless tokens, surfaced honestly rather than crashing.
    throw AppError.unauthorized('Account no longer exists');
  }

  res.status(200).json({ user: toPublicUser(user) });
}
