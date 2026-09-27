import type { Request, RequestHandler } from 'express';
import { consumeRateLimit } from '../lib/rate-limit.js';
import { AppError } from '../lib/app-error.js';
import { hashToken } from '../lib/crypto.js';

export interface RateLimitRule {
  bucket: string;
  limit: number;
  windowSeconds: number;
}

/**
 * Per-IP rate limiting, applied as middleware ahead of everything else on a route.
 *
 * It runs before `validate` and before the controller on purpose: the point is to
 * refuse the request cheaply. Validating a body or hashing a password first would
 * mean an attacker still gets to spend our CPU on every blocked attempt, which is
 * most of what the limit was meant to prevent.
 */
export function rateLimitByIp(rule: RateLimitRule): RequestHandler {
  return createLimiter(rule, (req) => req.ip ?? 'unknown');
}

/**
 * Rate limiting keyed on the submitted email as well as the IP.
 *
 * Per-IP alone is not enough against a distributed attack: a botnet has thousands
 * of addresses but still has to guess one account. Keying on the account closes
 * that, and the email is HASHED into the key so plaintext addresses are not
 * sitting in Redis where a memory dump or an errant KEYS scan would expose them.
 *
 * Applied to every attempt, including for addresses that do not exist -- an
 * endpoint that only counted real accounts would answer "does this email exist?"
 * through its own rate-limit headers.
 */
export function rateLimitByEmail(rule: RateLimitRule): RequestHandler {
  return createLimiter(rule, (req) => {
    const body = req.body as { email?: unknown } | undefined;
    const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';

    return email ? `email:${hashToken(email)}` : `ip:${req.ip ?? 'unknown'}`;
  });
}

function createLimiter(
  rule: RateLimitRule,
  resolveIdentifier: (req: Request) => string,
): RequestHandler {
  return (req, res, next) => {
    void consumeRateLimit({
      bucket: rule.bucket,
      identifier: resolveIdentifier(req),
      limit: rule.limit,
      windowSeconds: rule.windowSeconds,
    })
      .then((result) => {
        // The draft IETF RateLimit headers. Sent on every response, not just
        // rejections, so a well-behaved client can slow down before being cut off
        // instead of discovering the limit by hitting it.
        res.setHeader('RateLimit-Limit', result.limit);
        res.setHeader('RateLimit-Remaining', result.remaining);
        res.setHeader('RateLimit-Reset', result.resetSeconds);

        if (result.limited) {
          // Retry-After is the one header a client genuinely needs here: it turns
          // "try again later" into a number, so retries do not become their own
          // small denial of service.
          res.setHeader('Retry-After', result.resetSeconds);
          next(AppError.rateLimited('Too many requests. Please try again later.'));
          return;
        }

        next();
      })
      .catch(next);
  };
}
