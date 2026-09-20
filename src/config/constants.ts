/**
 * Error codes returned to clients as `{ error: { code, message } }`.
 *
 * These are part of the public API contract: a consuming app switches on `code`,
 * never on the human-readable `message`. Messages can be reworded freely; codes
 * cannot, so treat a change here as a breaking API change.
 */
export const ErrorCode = {
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  NOT_FOUND: 'NOT_FOUND',
  CONFLICT: 'CONFLICT',
  RATE_LIMITED: 'RATE_LIMITED',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
} as const;

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

/**
 * Cookie name for the refresh token.
 *
 * The refresh token travels in an httpOnly cookie rather than a JSON response
 * body: httpOnly means JavaScript on the page cannot read it, so an XSS bug can
 * no longer walk off with a 7-day credential. The short-lived access token is
 * the one handed to JS.
 */
export const REFRESH_TOKEN_COOKIE = 'refresh_token';

/** Path the refresh cookie is scoped to, so it is not sent on every single request. */
export const REFRESH_TOKEN_COOKIE_PATH = '/api/v1/auth';

/**
 * How long an email verification link stays valid.
 *
 * Long enough that someone can finish the flow the next morning, short enough
 * that a link sitting in an abandoned inbox does not stay usable forever.
 */
export const EMAIL_VERIFICATION_TTL_SECONDS = 60 * 60 * 24;
