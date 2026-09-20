import type { Role } from '../generated/prisma/enums.js';

/**
 * Adds `req.user` to Express's Request type.
 *
 * The authenticate middleware attaches the verified token payload here, and
 * every handler downstream reads it from the same place. Declaring it on the
 * global Express namespace is what makes that typed end to end instead of a
 * cast in each controller.
 */
declare global {
  namespace Express {
    interface AuthenticatedUser {
      id: string;
      role: Role;
    }

    interface Request {
      // Optional, because it is only populated on routes that ran authenticate.
      // A handler that needs it non-optionally should sit behind that middleware.
      user?: AuthenticatedUser;
    }
  }
}

export {};
