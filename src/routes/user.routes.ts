import { Router } from 'express';
import { asyncHandler } from '../middleware/async-handler.js';
import { validate } from '../middleware/validate.js';
import { authenticate } from '../middleware/authenticate.js';
import { requirePermission, requireSelfOrPermission } from '../middleware/authorize.js';
import { requireVerifiedEmail } from '../middleware/require-verified-email.js';
import { Permission } from '../config/permissions.js';
import * as userController from '../controllers/user.controller.js';
import { listUsersQuerySchema, updateRoleSchema, userIdParamSchema } from '../validators/user.validators.js';

/**
 * User management. The guard stack reads top to bottom on every route below:
 *
 *   authenticate          who are you?            (401 if unanswerable)
 *   requireVerifiedEmail  is your address real?   (403)
 *   requirePermission     may you do this?        (403)
 *   validate              is the input well-formed?
 *   controller            do it
 *
 * Ordering is not cosmetic. Authentication precedes authorization because "may
 * you" is unanswerable until "who are you" is settled. Validation comes last of
 * the guards so that an unauthorized caller gets 403 rather than a 400 that
 * would confirm which field names and formats the endpoint expects.
 */
export const userRouter: Router = Router();

// Applied to every route in this router rather than repeated per line: these are
// privileged operations, and an unverified address means nobody has proven they
// control the mailbox that account recovery would go to.
userRouter.use(authenticate, requireVerifiedEmail);

userRouter.get(
  '/',
  requirePermission(Permission.USERS_READ),
  validate({ query: listUsersQuerySchema }),
  asyncHandler(userController.list),
);

// Ownership, not just role: you may always read yourself. That rule is a
// relationship between actor and resource, which a role table alone cannot say.
//
// Param validation runs before the guard here, unlike the routes above, because
// the guard compares that param against the caller's id and should not be handed
// an unvalidated string.
userRouter.get(
  '/:id',
  validate({ params: userIdParamSchema }),
  requireSelfOrPermission('id', Permission.USERS_READ),
  asyncHandler(userController.getById),
);

userRouter.patch(
  '/:id/role',
  requirePermission(Permission.USERS_MANAGE_ROLES),
  validate({ params: userIdParamSchema, body: updateRoleSchema }),
  asyncHandler(userController.updateRole),
);

userRouter.delete(
  '/:id',
  requirePermission(Permission.USERS_DELETE),
  validate({ params: userIdParamSchema }),
  asyncHandler(userController.remove),
);
