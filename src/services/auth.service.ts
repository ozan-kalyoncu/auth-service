import { prisma } from '../lib/prisma.js';
import { AppError } from '../lib/app-error.js';
import { burnPasswordVerification, verifyPassword } from '../lib/password.js';
import { buildDuplicateRegistrationEmail, sendEmail } from '../lib/mailer.js';
import { logger } from '../lib/logger.js';
import { createUserWithPassword, findUserByEmail, markEmailVerified } from './user.service.js';
import { consumeVerificationToken, sendVerificationEmail } from './verification.service.js';
import { issueAccessToken, type IssuedTokens } from './token.service.js';
import {
  issueRefreshToken,
  revokeAllUserTokens,
  revokeRefreshToken,
  rotateRefreshToken,
} from './refresh-token.service.js';
import { toPublicUser, type PublicUser } from './user.service.js';
import { assertNotLocked, clearFailures, recordFailure } from './brute-force.service.js';

/**
 * Registers a new account.
 *
 * Note what this does NOT do: tell the caller whether the email was already
 * taken. A 409 "email already registered" is the conventional REST answer, but
 * it is also a user-enumeration oracle -- anyone can feed a list of addresses to
 * /register and learn which ones have accounts here, which is valuable for
 * phishing and credential stuffing.
 *
 * So both branches look identical from outside: same status, same body, same
 * rough timing. The existing-account branch instead sends an email to the
 * address on file ("someone tried to register with your email"), which reaches
 * the real owner and tells an attacker nothing.
 *
 * The trade-off is a slightly unusual API -- clients cannot show "that email is
 * taken" at signup, and the user finds out via email. Accepted deliberately here;
 * the same reasoning is why login returns one generic failure message.
 */
export async function register(email: string, password: string): Promise<void> {
  const existing = await findUserByEmail(email);

  if (existing) {
    // Deliberately not an error. Log it for ourselves so the pattern is visible
    // in monitoring, then take the branch that looks identical to the caller.
    logger.info({ userId: existing.id }, 'Registration attempted for existing account');
    await sendEmail(buildDuplicateRegistrationEmail(email));
    return;
  }

  const user = await createUserWithPassword(email, password);
  await sendVerificationEmail(user.id, user.email);

  logger.info({ userId: user.id }, 'User registered');
}

export interface LoginResult {
  user: PublicUser;
  tokens: IssuedTokens;
  /** Raw refresh token. The controller puts it in an httpOnly cookie and nothing else stores it. */
  refreshToken: string;
}

/**
 * Authenticates an email/password pair.
 *
 * Every failure -- unknown email, wrong password -- raises the SAME error. If
 * "no account with that email" were distinguishable from "wrong password", an
 * attacker could harvest valid addresses without ever guessing a password.
 */
export async function login(email: string, password: string, ip: string): Promise<LoginResult> {
  // Checked before anything else, including before the user lookup: a locked
  // account should cost an attacker one Redis read, not a database query and a
  // deliberately-slow Argon2 verification.
  await assertNotLocked(email);

  const user = await findUserByEmail(email);

  if (!user || !user.passwordHash) {
    // Two cases land here: no such user, and an OAuth-only account that has no
    // password to check (milestone 5). Both still pay the cost of a password
    // verification, so this path takes about as long as a real wrong-password
    // attempt and the timing difference stops being an enumeration signal.
    await burnPasswordVerification(password);
    await recordLoginAttempt(user?.id ?? null, ip, false);

    // Counted even for an email with no account. Skipping it would make the
    // lockout itself an oracle: an attacker could tell real addresses from
    // fictional ones by which ones can be locked.
    await recordFailure(email);

    throw AppError.unauthorized('Invalid email or password');
  }

  const passwordMatches = await verifyPassword(user.passwordHash, password);

  if (!passwordMatches) {
    await recordLoginAttempt(user.id, ip, false);
    await recordFailure(email);
    throw AppError.unauthorized('Invalid email or password');
  }

  await recordLoginAttempt(user.id, ip, true);

  // A correct password clears the run of failures. Otherwise someone who
  // mistyped four times and then succeeded would stay one slip from a lock.
  await clearFailures(email);

  // An unverified email is NOT blocked from logging in. The account simply stays
  // unverified, and routes that need a confirmed address guard themselves with
  // requireVerifiedEmail. Blocking login outright is also defensible, but it
  // leaves the user with no signed-in way to trigger a new verification email.
  const refreshToken = await issueRefreshToken(user.id);

  return { user: toPublicUser(user), tokens: issueAccessToken(user), refreshToken };
}

/**
 * Exchanges a valid refresh token for a new access token AND a new refresh token.
 *
 * The rotation and reuse detection live in refresh-token.service; this wrapper
 * exists so the controller depends on one auth surface rather than reaching into
 * two services.
 */
export async function refreshSession(rawToken: string): Promise<LoginResult> {
  const { rawToken: nextToken, user } = await rotateRefreshToken(rawToken);

  return { user: toPublicUser(user), tokens: issueAccessToken(user), refreshToken: nextToken };
}

/**
 * Logs out one session.
 *
 * Only the refresh token is revoked; the access token already in the client's
 * hands stays valid until it expires. That is the accepted cost of stateless
 * access tokens -- checking a revocation list on every request would undo the
 * reason they exist. A 15 minute TTL is what bounds the exposure, and anything
 * needing instant cut-off (a banned account) should check state per request.
 */
export async function logout(rawToken: string | undefined): Promise<void> {
  // No token presented is not an error: logging out twice, or with an expired
  // session, should still leave the client logged out.
  if (!rawToken) return;

  await revokeRefreshToken(rawToken);
}

/** Signs a user out of every device by revoking all of their live refresh tokens. */
export async function logoutAllSessions(userId: string): Promise<number> {
  const revoked = await revokeAllUserTokens(userId);

  logger.info({ userId, sessionsRevoked: revoked }, 'All sessions revoked');

  return revoked;
}

/**
 * Completes email verification.
 *
 * The token is consumed (read and deleted atomically) before anything else, so a
 * link cannot be replayed even if the update below fails.
 */
export async function verifyEmail(token: string): Promise<void> {
  const userId = await consumeVerificationToken(token);

  if (!userId) {
    throw AppError.badRequest('Verification link is invalid or has expired');
  }

  await markEmailVerified(userId);
  logger.info({ userId }, 'Email verified');
}

/**
 * Re-sends a verification email.
 *
 * Like register, this reveals nothing: an unknown address and an already-verified
 * account both return normally, so the endpoint cannot be used to probe which
 * emails exist or which are confirmed.
 */
export async function resendVerificationEmail(email: string): Promise<void> {
  const user = await findUserByEmail(email);

  if (!user || user.isEmailVerified) return;

  await sendVerificationEmail(user.id, user.email);
}

/**
 * Records an attempt whether it succeeded or failed.
 *
 * This table is the durable audit trail behind brute-force protection in
 * milestone 6, and the reason failures are stored with a null userId when the
 * email is unknown: a burst of attempts against non-existent accounts from one
 * IP is itself the signal worth alerting on.
 */
async function recordLoginAttempt(
  userId: string | null,
  ip: string,
  success: boolean,
): Promise<void> {
  try {
    await prisma.loginAttempt.create({ data: { userId, ip, success } });
  } catch (error) {
    // Audit logging must never be the reason a legitimate login fails. Log and
    // continue rather than turning a write hiccup into a 500 for the user.
    logger.error({ err: error }, 'Failed to record login attempt');
  }
}
