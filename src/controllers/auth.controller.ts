import type { Request, Response } from 'express';
import * as authService from '../services/auth.service.js';
import { findUserById } from '../services/user.service.js';
import { toPublicUser } from '../services/user.service.js';
import { requireUser } from '../middleware/authenticate.js';
import { AppError } from '../lib/app-error.js';
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

  res.status(200).json({
    user: result.user,
    ...result.tokens,
  });
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
