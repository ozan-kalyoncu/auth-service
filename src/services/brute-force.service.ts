import { redis } from '../lib/redis.js';
import { hashToken } from '../lib/crypto.js';
import { AppError } from '../lib/app-error.js';
import { logger } from '../lib/logger.js';
import { BRUTE_FORCE } from '../config/constants.js';

/**
 * Per-account brute-force protection with exponential backoff.
 *
 * Distinct from the per-IP rate limiter, and both are needed: per-IP stops one
 * machine hammering the service, but an attacker with a botnet has thousands of
 * addresses and still only needs to guess one account's password. This counts
 * consecutive failures against the ACCOUNT, wherever they come from.
 *
 * Backoff rather than permanent lockout, on purpose. A lock that never lifts
 * turns the protection into the attack: anyone who knows your email can lock you
 * out of your own account by failing to log in five times. Doubling delays make
 * sustained guessing hopeless within a handful of attempts -- at the ceiling, an
 * attacker gets 24 tries a day -- while an honest user who mistypes their
 * password twice notices nothing, and the worst case is waiting an hour.
 *
 * Counters live in Redis rather than the LoginAttempt table because this is read
 * on the hot path of every login. The table is still written for the audit trail;
 * these two answer different questions ("is this account under attack right
 * now?" vs "what happened last Tuesday?").
 */

function failureKey(email: string): string {
  // Hashed: Redis should not hold a list of plaintext addresses that are
  // currently under attack -- that is a target in itself.
  return `bruteforce:failures:${hashToken(email)}`;
}

function lockKey(email: string): string {
  return `bruteforce:lock:${hashToken(email)}`;
}

/**
 * Throws if the account is currently locked.
 *
 * Called before the password is even checked, so a locked account costs an
 * attacker one Redis read rather than a full Argon2 verification.
 */
export async function assertNotLocked(email: string): Promise<void> {
  const ttl = await redis.ttl(lockKey(email));

  if (ttl > 0) {
    throw new AppError(429, 'RATE_LIMITED', 'Too many failed attempts. Try again later.', {
      retryAfterSeconds: ttl,
    });
  }
}

/**
 * Records a failed attempt and locks the account once the threshold is passed.
 *
 * Returns the lock duration applied, or 0 if the account is still under the
 * threshold.
 */
export async function recordFailure(email: string): Promise<number> {
  const failures = await redis.incr(failureKey(email));

  // Refresh the window on every failure: a run of attempts is only forgotten
  // after a full quiet hour, not an hour after the first one.
  await redis.expire(failureKey(email), BRUTE_FORCE.failureWindowSeconds);

  if (failures < BRUTE_FORCE.threshold) return 0;

  // 1st lock at the threshold, then doubling: 60s, 120s, 240s ... capped.
  const overage = failures - BRUTE_FORCE.threshold;
  const lockSeconds = Math.min(
    BRUTE_FORCE.baseLockSeconds * 2 ** overage,
    BRUTE_FORCE.maxLockSeconds,
  );

  await redis.set(lockKey(email), '1', 'EX', lockSeconds);

  logger.warn({ failures, lockSeconds }, 'Account locked after repeated failed logins');

  return lockSeconds;
}

/**
 * Clears the failure count after a successful login.
 *
 * Without this, a user who mistyped four times and then succeeded would still be
 * one slip away from a lock days later.
 */
export async function clearFailures(email: string): Promise<void> {
  await redis.del(failureKey(email), lockKey(email));
}
