import { Router } from 'express';
import { asyncHandler } from '../middleware/async-handler.js';
import { validate } from '../middleware/validate.js';
import { authenticate } from '../middleware/authenticate.js';
import { rateLimitByEmail, rateLimitByIp } from '../middleware/rate-limit.js';
import { RATE_LIMITS } from '../config/constants.js';
import * as authController from '../controllers/auth.controller.js';
import { oauthRouter } from './oauth.routes.js';
import {
  loginSchema,
  refreshSchema,
  registerSchema,
  resendVerificationSchema,
  verifyEmailQuerySchema,
} from '../validators/auth.validators.js';

/**
 * Route definitions read as a pipeline: rate limit -> validate -> authenticate
 * -> handler. Everything guarding an endpoint is visible on one line, so
 * reviewing "is this route protected?" means reading the route file rather than
 * auditing the controller.
 *
 * Rate limiting is FIRST on every unauthenticated route. Putting it after
 * validation would mean an attacker still gets to spend our CPU parsing bodies
 * and hashing passwords on requests we were going to reject anyway.
 */
export const authRouter: Router = Router();

authRouter.post(
  '/register',
  rateLimitByIp(RATE_LIMITS.register),
  validate({ body: registerSchema }),
  asyncHandler(authController.register),
);

// Two limiters, because they stop different attacks: by IP catches one machine
// hammering the endpoint, by email catches a botnet spread across thousands of
// addresses all guessing the same account.
authRouter.post(
  '/login',
  rateLimitByIp(RATE_LIMITS.login),
  rateLimitByEmail(RATE_LIMITS.login),
  validate({ body: loginSchema }),
  asyncHandler(authController.login),
);

// GET, because this is opened by clicking a link in an email. The token travels
// in the query string, which is why it is single-use and short-lived: URLs leak
// into browser history, server logs and Referer headers far more readily than
// request bodies do.
authRouter.get(
  '/verify-email',
  rateLimitByIp(RATE_LIMITS.verifyEmail),
  validate({ query: verifyEmailQuerySchema }),
  asyncHandler(authController.verifyEmail),
);

// Tightly limited: this endpoint sends email, so an unlimited one is a free
// spam cannon pointed at whatever address the caller names.
authRouter.post(
  '/resend-verification',
  rateLimitByIp(RATE_LIMITS.resendVerification),
  rateLimitByEmail(RATE_LIMITS.resendVerification),
  validate({ body: resendVerificationSchema }),
  asyncHandler(authController.resendVerification),
);

// Refresh and logout are NOT behind `authenticate`: they are reached with an
// expired access token by definition -- that is the situation they exist for.
// The refresh token itself is the credential, and it is checked in the service.
//
// The limit here is generous: a legitimate client refreshes on a timer, and one
// left open in a browser tab overnight is not an attack.
authRouter.post(
  '/refresh',
  rateLimitByIp(RATE_LIMITS.refresh),
  validate({ body: refreshSchema }),
  asyncHandler(authController.refresh),
);

authRouter.post('/logout', validate({ body: refreshSchema }), asyncHandler(authController.logout));

// Signing out every device acts on the whole account, so it requires a currently
// valid access token rather than just possession of one session's cookie.
authRouter.post('/logout-all', authenticate, asyncHandler(authController.logoutAll));

authRouter.get('/me', authenticate, asyncHandler(authController.getCurrentUser));

// Social login lives under /auth/oauth/*.
authRouter.use('/oauth', oauthRouter);
