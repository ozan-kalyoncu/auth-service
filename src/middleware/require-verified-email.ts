import type { RequestHandler } from 'express';
import { AppError } from '../lib/app-error.js';
import { requireUser } from './authenticate.js';
import { findUserById } from '../services/user.service.js';

/**
 * Guards routes that need a confirmed email address.
 *
 * Verification status is checked against the DATABASE, not the access token,
 * even though reading it from the token would be free. A user who verifies their
 * email still holds a token minted before that moment; trusting the token would
 * keep them locked out for up to 15 minutes with no way to force a refresh.
 *
 * So this is the deliberate opposite trade-off from `role` in the RBAC guard:
 * role changes are rare and tolerate being stale, verification happens once and
 * must take effect immediately. Only routes that opt in pay the extra query.
 */
export const requireVerifiedEmail: RequestHandler = (req, _res, next) => {
  const { id } = requireUser(req);

  findUserById(id)
    .then((user) => {
      if (!user) {
        // Authenticated with a valid token, but the account is gone -- a token
        // issued before the user was deleted.
        next(AppError.unauthorized('Account no longer exists'));
        return;
      }

      if (!user.isEmailVerified) {
        next(AppError.forbidden('Email address must be verified to access this resource'));
        return;
      }

      next();
    })
    .catch(next);
};
