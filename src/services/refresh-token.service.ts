import { prisma } from '../lib/prisma.js';
import { generateSecureToken, hashToken } from '../lib/crypto.js';
import { AppError } from '../lib/app-error.js';
import { logger } from '../lib/logger.js';
import { env } from '../config/env.js';
import { parseDurationToSeconds } from './token.service.js';
import type { UserModel as User } from '../generated/prisma/models.js';

/**
 * Refresh tokens: long-lived credentials that buy new access tokens.
 *
 * Why two token types at all? An access token is verified by signature alone, so
 * checking it costs no database round trip -- but that also means it cannot be
 * revoked before it expires. A refresh token is the opposite: every use hits the
 * database, so it CAN be revoked instantly, at the cost of a query. Splitting
 * them buys cheap authentication on every request plus real revocation, instead
 * of having to choose one.
 *
 * These are opaque random strings, not JWTs, which is why there is no refresh
 * signing secret in the config. A JWT would let us reject a malformed token by
 * signature alone, but rotation has to read and write the row regardless, so the
 * signature buys nothing on the happy path. An opaque token is shorter, carries
 * no readable claims, and cannot be forged by anyone who obtains a signing key.
 *
 * The cost: a garbage token still costs one indexed lookup to reject, where a
 * signature check would have been free. That is a rate-limiting problem
 * (milestone 6), not a reason to sign.
 */

export interface RotationResult {
  rawToken: string;
  user: User;
}

function refreshTokenTtlSeconds(): number {
  return parseDurationToSeconds(env.JWT_REFRESH_TTL);
}

function expiryFromNow(): Date {
  return new Date(Date.now() + refreshTokenTtlSeconds() * 1000);
}

/**
 * Mints a refresh token and stores only its hash.
 *
 * Returns the raw token, which the caller puts in the cookie. After this
 * function returns, the raw value exists nowhere on the server -- so a database
 * leak yields hashes that cannot be replayed, exactly as with passwords.
 */
export async function issueRefreshToken(userId: string): Promise<string> {
  const rawToken = generateSecureToken();

  await prisma.refreshToken.create({
    data: { tokenHash: hashToken(rawToken), userId, expiresAt: expiryFromNow() },
  });

  return rawToken;
}

/**
 * Exchanges a refresh token for a fresh one -- "rotation".
 *
 * Every refresh invalidates the token that was used and issues a new one. The
 * point is what it makes detectable: a refresh token is a bearer credential, so
 * if one is stolen, nothing about the token itself distinguishes the thief from
 * the real user. But only one of them can use it FIRST. The loser presents a
 * token that has already been spent, and that second use is the alarm.
 *
 * Without rotation a stolen token works quietly for its full lifetime and the
 * theft is never visible at all.
 */
export async function rotateRefreshToken(rawToken: string): Promise<RotationResult> {
  const existing = await prisma.refreshToken.findUnique({
    where: { tokenHash: hashToken(rawToken) },
    include: { user: true },
  });

  if (!existing) {
    // Never seen, or already pruned. Nothing to revoke -- the token means nothing.
    throw AppError.unauthorized('Invalid refresh token');
  }

  if (existing.revokedAt) {
    // A revoked token was presented -- but HOW it was revoked decides whether
    // this is an attack or just a stale client.
    //
    // replacedBy set means the token was SPENT in a rotation and someone is now
    // presenting it a second time. That is the theft signal: either an attacker
    // stole it and the real user rotated first, or the attacker rotated first
    // and the real user is replaying. We cannot tell the two parties apart, so
    // we trust neither and cut every session.
    if (existing.replacedBy) {
      await handleTokenReuse(existing.userId, existing.id);
      throw AppError.unauthorized('Refresh token has already been used; all sessions revoked');
    }

    // replacedBy empty means it was revoked deliberately -- by logout, or by the
    // cascade below. Re-triggering the alarm here would bury the genuine signal:
    // after one reuse event, every other device would report "reuse" on its next
    // refresh, turning a single alert into a flood.
    logger.info({ userId: existing.userId }, 'Revoked refresh token presented');
    throw AppError.unauthorized('Refresh token has been revoked');
  }

  if (existing.expiresAt <= new Date()) {
    // Expired but unused. Not an attack -- just an old session. Revoke the row so
    // a later presentation is not mistaken for reuse, and make the user log in.
    await prisma.refreshToken.update({
      where: { id: existing.id },
      data: { revokedAt: new Date() },
    });
    throw AppError.unauthorized('Refresh token has expired');
  }

  const newRawToken = generateSecureToken();

  // Issue-and-revoke must be one atomic unit. If the process died between the
  // two writes, a non-transactional version would either revoke the old token
  // without issuing a replacement (logging the user out) or leave two live
  // tokens (defeating rotation).
  await prisma.$transaction(async (tx) => {
    const replacement = await tx.refreshToken.create({
      data: { tokenHash: hashToken(newRawToken), userId: existing.userId, expiresAt: expiryFromNow() },
    });

    // The `revokedAt: null` guard is what makes concurrent refreshes safe. Two
    // requests can both read the row as valid a moment apart; only one of their
    // updates will match, and the loser's count of 0 rolls this transaction back
    // so it does not mint a second live token from the same parent.
    const revoked = await tx.refreshToken.updateMany({
      where: { id: existing.id, revokedAt: null },
      data: { revokedAt: new Date(), replacedBy: replacement.id },
    });

    if (revoked.count === 0) {
      throw AppError.unauthorized('Invalid refresh token');
    }
  });

  return { rawToken: newRawToken, user: existing.user };
}

/**
 * Responds to a detected reuse by revoking every live token for the user.
 *
 * This deliberately over-reaches: it signs the user out of every device, not just
 * the compromised chain. With the v1 schema there is no family/session id tying a
 * rotation chain together, and when a credential is known to have leaked, cutting
 * too much is far cheaper than leaving the attacker a working session. Adding a
 * `familyId` column later would let this target one chain instead.
 */
async function handleTokenReuse(userId: string, reusedTokenId: string): Promise<void> {
  const result = await prisma.refreshToken.updateMany({
    where: { userId, revokedAt: null },
    data: { revokedAt: new Date() },
  });

  // Logged at warn, not info: this is the one event in the whole service that
  // should page someone if it starts happening often.
  logger.warn(
    { userId, reusedTokenId, sessionsRevoked: result.count },
    'Refresh token reuse detected; revoked all sessions for user',
  );
}

/**
 * Revokes a single token -- what logout does.
 *
 * The row is marked revoked rather than deleted so the rotation chain stays
 * auditable, and so a later presentation of that token is recognised as reuse
 * instead of simply being unknown.
 */
export async function revokeRefreshToken(rawToken: string): Promise<void> {
  await prisma.refreshToken.updateMany({
    where: { tokenHash: hashToken(rawToken), revokedAt: null },
    data: { revokedAt: new Date() },
  });
}

/** Revokes every live session for a user -- "sign out everywhere". */
export async function revokeAllUserTokens(userId: string): Promise<number> {
  const result = await prisma.refreshToken.updateMany({
    where: { userId, revokedAt: null },
    data: { revokedAt: new Date() },
  });

  return result.count;
}

/**
 * Deletes rows that are long past useful, to stop the table growing forever.
 *
 * Not wired to a scheduler here -- in a real deployment this would be a cron job
 * or a pg_cron task. Expired tokens are kept for a grace period rather than
 * deleted on expiry, so that reuse of a recently-expired token is still
 * recognisable rather than looking like an unknown token.
 */
export async function pruneExpiredTokens(gracePeriodDays = 30): Promise<number> {
  const cutoff = new Date(Date.now() - gracePeriodDays * 86400 * 1000);

  const result = await prisma.refreshToken.deleteMany({
    where: { expiresAt: { lt: cutoff } },
  });

  return result.count;
}
