import type { CookieOptions, Response } from 'express';
import { isProduction } from '../config/env.js';
import { REFRESH_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE_PATH } from '../config/constants.js';

/**
 * The refresh token is delivered as a cookie rather than in the JSON body.
 *
 * Access token vs refresh token, and why they are carried differently:
 *   - the access token is short-lived and goes in an Authorization header, so
 *     client JavaScript has to be able to read it;
 *   - the refresh token is long-lived, so handing it to JavaScript means one XSS
 *     bug leaks a credential worth 7 days. httpOnly puts it somewhere script
 *     cannot reach, while the browser still attaches it automatically.
 */
function cookieOptions(maxAgeSeconds: number): CookieOptions {
  return {
    // Not readable by document.cookie or any script on the page.
    httpOnly: true,

    // HTTPS only. Disabled outside production because localhost is plain http
    // and the browser would silently drop the cookie.
    secure: isProduction,

    // Blocks CSRF against the refresh endpoint: the browser refuses to attach
    // this cookie to requests originating from another site, so an attacker's
    // page cannot silently POST /auth/refresh and rotate a victim's session.
    //
    // The trade-off is real: a single-page app served from a DIFFERENT origin
    // than this API will not send the cookie either, and would need
    // sameSite: 'none' + secure (and then its own CSRF defence). 'strict' is
    // the safer default; the body fallback on /auth/refresh covers non-browser
    // clients.
    sameSite: 'strict',

    // Scoped so the cookie is attached only to the auth routes that need it,
    // instead of riding along on every request to the API.
    path: REFRESH_TOKEN_COOKIE_PATH,

    // Express expects milliseconds.
    maxAge: maxAgeSeconds * 1000,
  };
}

export function setRefreshTokenCookie(res: Response, token: string, maxAgeSeconds: number): void {
  res.cookie(REFRESH_TOKEN_COOKIE, token, cookieOptions(maxAgeSeconds));
}

/**
 * Clears the cookie on logout.
 *
 * The options must match the ones it was set with -- a browser treats cookies as
 * distinct if path or sameSite differ, so clearing with mismatched options
 * silently leaves the original in place.
 */
export function clearRefreshTokenCookie(res: Response): void {
  const { maxAge: _maxAge, ...options } = cookieOptions(0);
  res.clearCookie(REFRESH_TOKEN_COOKIE, options);
}
