import { Router } from 'express';
import { asyncHandler } from '../middleware/async-handler.js';
import { validate } from '../middleware/validate.js';
import { authenticate } from '../middleware/authenticate.js';
import * as authController from '../controllers/auth.controller.js';
import {
  loginSchema,
  registerSchema,
  resendVerificationSchema,
  verifyEmailQuerySchema,
} from '../validators/auth.validators.js';

/**
 * Route definitions read as a pipeline: validate -> authenticate -> handler.
 * Everything guarding an endpoint is visible on one line, so reviewing "is this
 * route protected?" means reading the route file, not auditing the controller.
 *
 * Rate limiting slots in ahead of validate on /register and /login in milestone 6.
 */
export const authRouter: Router = Router();

authRouter.post(
  '/register',
  validate({ body: registerSchema }),
  asyncHandler(authController.register),
);

authRouter.post('/login', validate({ body: loginSchema }), asyncHandler(authController.login));

// GET, because this is opened by clicking a link in an email. The token travels
// in the query string, which is why it is single-use and short-lived: URLs leak
// into browser history, server logs and Referer headers far more readily than
// request bodies do.
authRouter.get(
  '/verify-email',
  validate({ query: verifyEmailQuerySchema }),
  asyncHandler(authController.verifyEmail),
);

authRouter.post(
  '/resend-verification',
  validate({ body: resendVerificationSchema }),
  asyncHandler(authController.resendVerification),
);

authRouter.get('/me', authenticate, asyncHandler(authController.getCurrentUser));
