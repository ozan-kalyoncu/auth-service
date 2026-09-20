import { AppError } from '../lib/app-error.js';
import { logger } from '../lib/logger.js';
import { deleteUser, findUserById, toPublicUser, updateUserRole } from './user.service.js';
import { revokeAllUserTokens } from './refresh-token.service.js';
import type { PublicUser } from './user.service.js';
import type { Role } from '../generated/prisma/enums.js';

/**
 * Administrative actions on other people's accounts.
 *
 * Kept apart from user.service (which is plain data access) because these carry
 * policy: who may be acted on, and what else must happen as a consequence.
 */

/**
 * Changes a user's role, then ends all of their sessions.
 *
 * The revocation is the part that is easy to miss. `role` is baked into every
 * access token so authorization needs no database lookup -- which means a
 * demoted admin keeps admin rights inside any token already issued. Revoking
 * their refresh tokens cannot claw those back, but it stops them being renewed,
 * so the stale privilege window closes at the access token's TTL (15 minutes)
 * instead of the refresh token's (7 days).
 *
 * Shrinking that window further means checking the role per request, which is
 * exactly the database round trip the stateless token exists to avoid. 15
 * minutes of stale privilege is the price of that speed, and it is a choice, not
 * an oversight.
 */
export async function changeUserRole(
  actorId: string,
  targetUserId: string,
  role: Role,
): Promise<PublicUser> {
  // Self-demotion is how an organisation locks itself out of its own admin
  // tooling -- the last superadmin drops to USER and nobody can promote anyone
  // back. Changing someone else's role is fine; changing your own is not.
  if (actorId === targetUserId) {
    throw AppError.forbidden('You cannot change your own role');
  }

  const target = await findUserById(targetUserId);

  if (!target) {
    throw AppError.notFound('User not found');
  }

  if (target.role === role) {
    // Not an error, but skip the session revocation: nothing changed, so there is
    // no reason to sign the user out.
    return toPublicUser(target);
  }

  const updated = await updateUserRole(targetUserId, role);
  const sessionsRevoked = await revokeAllUserTokens(targetUserId);

  logger.info(
    { actorId, targetUserId, from: target.role, to: role, sessionsRevoked },
    'User role changed',
  );

  return toPublicUser(updated);
}

/**
 * Deletes a user account.
 *
 * Refresh tokens and linked OAuth accounts cascade away with the row, so no
 * session survives the deletion.
 */
export async function removeUser(actorId: string, targetUserId: string): Promise<void> {
  // Same lockout reasoning as above, plus the obvious: an account cannot be the
  // one performing its own deletion and then keep serving the rest of the request.
  if (actorId === targetUserId) {
    throw AppError.forbidden('You cannot delete your own account through this endpoint');
  }

  const target = await findUserById(targetUserId);

  if (!target) {
    throw AppError.notFound('User not found');
  }

  await deleteUser(targetUserId);

  logger.info({ actorId, targetUserId, role: target.role }, 'User deleted');
}
