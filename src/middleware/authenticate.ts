import type { RequestHandler } from 'express';
import { verifyAccessToken } from '../lib/jwt.js';
import { AppError } from '../lib/app-error.js';

/**
 * Authentication guard: proves WHO the caller is. Authorization -- what they are
 * allowed to do -- is a separate middleware (RBAC, milestone 4), because the two
 * questions fail differently: no identity is a 401, insufficient permission is a
 * 403, and mixing them makes both harder to reason about.
 *
 * This runs as middleware ahead of the controller rather than as a check inside
 * it, so an unauthenticated request is rejected before any business logic, any
 * database query, or any chance of a handler forgetting to call it.
 */
export const authenticate: RequestHandler = (req, _res, next) => {
  const header = req.headers.authorization;

  if (!header?.startsWith('Bearer ')) {
    next(AppError.unauthorized('Missing or malformed Authorization header'));
    return;
  }

  const token = header.slice('Bearer '.length).trim();

  if (!token) {
    next(AppError.unauthorized('Missing or malformed Authorization header'));
    return;
  }

  try {
    // Verification is pure signature + claim checking -- no database round trip.
    // That is the whole point of a stateless access token: every request would
    // otherwise cost a user lookup. The price is that a token stays valid until
    // it expires, even if the user is deleted, which is why the TTL is 15 minutes.
    const payload = verifyAccessToken(token);

    req.user = { id: payload.sub, role: payload.role };
    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Reads `req.user` where a route is known to sit behind `authenticate`.
 *
 * Keeps the non-null assertion in one audited place instead of every controller.
 */
export function requireUser(req: { user?: Express.AuthenticatedUser }): Express.AuthenticatedUser {
  if (!req.user) {
    // Reaching here means a route was wired without the authenticate middleware,
    // which is a programming error, not a client error -- hence a 500, not a 401.
    throw AppError.internal('Route requires authentication middleware');
  }

  return req.user;
}
