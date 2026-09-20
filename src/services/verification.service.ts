import { redis } from '../lib/redis.js';
import { generateSecureToken, hashToken } from '../lib/crypto.js';
import { buildVerificationEmail, sendEmail } from '../lib/mailer.js';
import { env } from '../config/env.js';
import { EMAIL_VERIFICATION_TTL_SECONDS } from '../config/constants.js';

/**
 * Email verification tokens live in Redis rather than Postgres.
 *
 * They are single-use and expire in 24 hours, so they are exactly the kind of
 * ephemeral state Redis handles well: `SET key value EX 86400` expires the token
 * automatically, with no cleanup job scanning a table for stale rows.
 *
 * The trade-off, stated honestly: if Redis is flushed, pending verification links
 * stop working and users must request a new one. That is an acceptable cost for a
 * 24-hour token. Refresh tokens are NOT treated this way -- they are long-lived
 * and auditable, so they live in Postgres (milestone 3).
 */
function verificationKey(tokenHash: string): string {
  // Namespaced so this service can share a Redis instance with other keys
  // (rate-limit counters arrive in milestone 6) without collisions.
  return `email-verification:${tokenHash}`;
}

/**
 * Issues a verification token and "sends" it.
 *
 * Only the HASH is stored. The raw token exists in the emailed link and nowhere
 * else -- so an attacker who reads the Redis contents still cannot verify
 * anyone's email, in the same way a stolen password-hash table cannot be
 * replayed as passwords.
 */
export async function sendVerificationEmail(userId: string, email: string): Promise<void> {
  const token = generateSecureToken();

  await redis.set(verificationKey(hashToken(token)), userId, 'EX', EMAIL_VERIFICATION_TTL_SECONDS);

  const verificationUrl = `${env.APP_BASE_URL}/api/v1/auth/verify-email?token=${token}`;
  await sendEmail(buildVerificationEmail(email, verificationUrl));
}

/**
 * Consumes a verification token, returning the user id it belongs to.
 *
 * GETDEL reads and deletes atomically, which is what makes the token single-use:
 * with a separate GET then DEL, two requests arriving at the same moment could
 * both read the token before either deleted it.
 */
export async function consumeVerificationToken(token: string): Promise<string | null> {
  const userId = await redis.getdel(verificationKey(hashToken(token)));
  return userId;
}
