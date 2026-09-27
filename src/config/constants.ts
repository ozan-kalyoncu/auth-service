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

/**
 * How long an in-flight OAuth login may take.
 *
 * Generous enough to sign in and approve at the provider, short enough that a
 * `state` left over in a closed tab stops being redeemable quickly.
 */
export const OAUTH_STATE_TTL_SECONDS = 60 * 10;

/** Cookie holding the OAuth `state`, so the callback can prove it began here. */
export const OAUTH_STATE_COOKIE = 'oauth_state';

export const OAUTH_STATE_COOKIE_PATH = '/api/v1/auth/oauth';

/**
 * Per-IP rate limits, tuned per endpoint rather than one global number.
 *
 * The limit reflects what legitimate use of THAT endpoint looks like. Nobody
 * registers five accounts an hour from one address by accident, but a browser
 * tab left open overnight will refresh its token a few dozen times, so the
 * numbers differ by an order of magnitude. A single global limit would have to
 * be set high enough for the busiest endpoint, which makes it useless for the
 * one that actually needs protecting.
 */
export const RATE_LIMITS = {
  login: { bucket: 'login', limit: 10, windowSeconds: 300 },
  register: { bucket: 'register', limit: 5, windowSeconds: 3600 },
  refresh: { bucket: 'refresh', limit: 60, windowSeconds: 300 },
  resendVerification: { bucket: 'resend-verification', limit: 3, windowSeconds: 3600 },
  verifyEmail: { bucket: 'verify-email', limit: 20, windowSeconds: 3600 },
  oauthStart: { bucket: 'oauth-start', limit: 20, windowSeconds: 300 },
  twoFactor: { bucket: 'two-factor', limit: 10, windowSeconds: 300 },
} as const;

/**
 * Brute-force protection on a single account, which is a different problem from
 * per-IP rate limiting: an attacker with a botnet has thousands of IPs but still
 * has to guess one account's password.
 *
 * After `threshold` consecutive failures the account is locked for a period that
 * doubles with each further failure. Exponential backoff makes sustained guessing
 * pointless within a few attempts, while an honest user who mistypes twice sees
 * nothing at all.
 */
export const BRUTE_FORCE = {
  /** Failures allowed before the first lock. */
  threshold: 5,
  /** First lock duration; doubles per failure beyond the threshold. */
  baseLockSeconds: 60,
  /** Ceiling, so an account is never locked out permanently by an attacker. */
  maxLockSeconds: 3600,
  /** How long a run of failures is remembered when no further attempts arrive. */
  failureWindowSeconds: 3600,
} as const;
