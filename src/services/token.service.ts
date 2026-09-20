import { signAccessToken } from '../lib/jwt.js';
import { env } from '../config/env.js';
import type { UserModel as User } from '../generated/prisma/models.js';

/**
 * Token issuing lives behind a service rather than being called straight from
 * the controller, so there is exactly one place that decides what a freshly
 * authenticated session receives -- used by login and by refresh alike.
 */
export interface IssuedTokens {
  accessToken: string;
  tokenType: 'Bearer';
  /** Seconds until the access token expires -- lets a client refresh proactively. */
  expiresIn: number;
}

export function issueAccessToken(user: User): IssuedTokens {
  return {
    accessToken: signAccessToken(user.id, user.role),
    tokenType: 'Bearer',
    expiresIn: parseDurationToSeconds(env.JWT_ACCESS_TTL),
  };
}

/**
 * Converts the "15m" / "7d" duration strings used in config into seconds.
 *
 * jsonwebtoken accepts those strings directly for signing, but the client needs a
 * number it can count down, and the refresh-token table needs a concrete expiry
 * date, so the same value is parsed once here.
 */
export function parseDurationToSeconds(duration: string): number {
  const match = /^(\d+)\s*(s|m|h|d)$/.exec(duration.trim());

  // A plain number is already seconds, which is also what jsonwebtoken assumes.
  if (!match) {
    const asNumber = Number(duration);
    if (Number.isFinite(asNumber)) return asNumber;
    throw new Error(`Invalid duration: ${duration}`);
  }

  const amount = Number(match[1]);
  const unit = match[2] as 's' | 'm' | 'h' | 'd';
  const multipliers = { s: 1, m: 60, h: 3600, d: 86400 } as const;

  return amount * multipliers[unit];
}
