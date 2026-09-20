import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import { AppError } from './app-error.js';
import type { Role } from '../generated/prisma/enums.js';

/**
 * What goes inside an access token.
 *
 * A JWT is signed, NOT encrypted -- anyone holding it can base64-decode and read
 * this payload. So it carries only what a client may see anyway, and never a
 * password hash, email verification token, or anything secret.
 *
 * `role` is included so the RBAC middleware (milestone 4) can authorize a request
 * without a database round trip. The trade-off: a role change does not take
 * effect until the current access token expires. That is precisely why access
 * tokens are short-lived -- 15 minutes bounds how long stale permissions survive.
 */
export interface AccessTokenPayload {
  /** Subject: the user id. `sub` is the standard JWT claim for "who this is about". */
  sub: string;
  role: Role;
  /**
   * Distinguishes token kinds. Milestone 3 adds refresh tokens; without this
   * field, a refresh token would be structurally valid as an access token and
   * could be replayed against protected endpoints.
   */
  type: 'access';
}

const ACCESS_TOKEN_TYPE = 'access';

/** Signs a short-lived access token for the given user. */
export function signAccessToken(userId: string, role: Role): string {
  const payload: AccessTokenPayload = { sub: userId, role, type: ACCESS_TOKEN_TYPE };

  return jwt.sign(payload, env.JWT_ACCESS_SECRET, {
    // Cast because the TTL is a free-form string from config, while the library
    // types it as a specific set of duration literals. token.service parses the
    // same value, so an unusable duration surfaces there.
    expiresIn: env.JWT_ACCESS_TTL as NonNullable<jwt.SignOptions['expiresIn']>,

    // issuer/audience are verified on the way back in. They stop a token minted
    // by some other service that happens to share this secret from being accepted
    // here, and stop OUR tokens being replayed at a different audience.
    issuer: env.JWT_ISSUER,
    audience: env.JWT_AUDIENCE,
  });
}

/**
 * Verifies an access token and returns its payload.
 *
 * Verification checks the signature (proving we minted it and nobody edited the
 * payload), the expiry, and the issuer/audience. Every failure is reported to the
 * client as the same generic 401: telling an attacker whether a token was
 * *expired* versus *forged* hands them information for free.
 */
export function verifyAccessToken(token: string): AccessTokenPayload {
  let decoded: unknown;

  try {
    decoded = jwt.verify(token, env.JWT_ACCESS_SECRET, {
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,

      // Pin the algorithm. Without this, a token whose header says
      // `"alg": "none"` -- or a symmetric-key forgery against an RS256 public
      // key -- can be accepted. It is the classic JWT vulnerability.
      algorithms: ['HS256'],
    });
  } catch {
    throw AppError.unauthorized('Invalid or expired token');
  }

  if (
    typeof decoded !== 'object' ||
    decoded === null ||
    (decoded as AccessTokenPayload).type !== ACCESS_TOKEN_TYPE
  ) {
    throw AppError.unauthorized('Invalid or expired token');
  }

  return decoded as AccessTokenPayload;
}
