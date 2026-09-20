import type { RequestHandler } from 'express';
import { AppError } from '../lib/app-error.js';
import { requireUser } from './authenticate.js';
import { roleHasPermission, type Permission } from '../config/permissions.js';
import type { Role } from '../generated/prisma/enums.js';

/**
 * Authorization guard. Runs AFTER `authenticate` and BEFORE the controller.
 *
 * Why middleware rather than a check inside the handler:
 *   - a forbidden request never reaches business logic, so the controller cannot
 *     leak data through an early query or an error message;
 *   - the guard is visible in the route definition, so answering "who can call
 *     this?" means reading one line, not auditing a function body;
 *   - it cannot be forgotten halfway down a handler that grew a second branch.
 *
 * 401 vs 403 is a real distinction, not a style choice: 401 means "I do not know
 * who you are, authenticate and try again", 403 means "I know exactly who you
 * are, and the answer is still no". Returning 401 for the second sends clients
 * into a pointless refresh-and-retry loop.
 */
export function requirePermission(...permissions: Permission[]): RequestHandler {
  return (req, _res, next) => {
    // Throws a 500 if the route was wired without `authenticate` -- a bug in our
    // routing, not a client error, and far better than defaulting to "deny" and
    // leaving a misconfigured route looking like a working one.
    const user = requireUser(req);

    // ALL listed permissions are required, not any. "Requires more" is the safe
    // default to get wrong; a route needing either/or can say so explicitly.
    const missing = permissions.filter(
      (permission) => !roleHasPermission(user.role, permission),
    );

    if (missing.length > 0) {
      // The message names the permission because this is an internal service and
      // the caller is a developer integrating against it -- knowing WHICH
      // capability is missing saves an afternoon. On a public-facing API this
      // would be a bare "Insufficient permissions".
      next(AppError.forbidden(`Missing required permission: ${missing.join(', ')}`));
      return;
    }

    next();
  };
}

/**
 * Guards by role name instead of permission.
 *
 * Deliberately the exception. It is here for the rare rule that is genuinely
 * about identity rather than capability ("superadmins only", regardless of what
 * superadmin can currently do). Reach for requirePermission first -- a codebase
 * full of role checks is the thing the permission layer exists to prevent.
 */
export function requireRole(...roles: Role[]): RequestHandler {
  return (req, _res, next) => {
    const user = requireUser(req);

    if (!roles.includes(user.role)) {
      next(AppError.forbidden('Insufficient permissions'));
      return;
    }

    next();
  };
}

/**
 * Allows the actor through if they are acting on their OWN record, or hold the
 * given permission.
 *
 * Ownership is the check that pure role tables cannot express: "users may read
 * themselves" is not a role, it is a relationship between the actor and the
 * resource. Keeping it as its own middleware stops that logic being reinvented,
 * slightly differently, in every controller that needs it.
 */
export function requireSelfOrPermission(
  paramName: string,
  permission: Permission,
): RequestHandler {
  return (req, _res, next) => {
    const user = requireUser(req);

    if (req.params[paramName] === user.id) {
      next();
      return;
    }

    if (roleHasPermission(user.role, permission)) {
      next();
      return;
    }

    // Same 403 either way: a user who may not read others must not be able to
    // tell an existing id from a non-existent one by the error they get back.
    next(AppError.forbidden('Insufficient permissions'));
  };
}
