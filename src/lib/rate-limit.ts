import { redis } from './redis.js';
import { logger } from './logger.js';

/**
 * Redis-backed fixed-window counter.
 *
 * Why Redis and not a Map in memory: the counter has to be shared. With four
 * containers behind a load balancer, an in-memory limit of 10 becomes an
 * effective limit of 40, and an attacker spreading attempts across instances
 * never trips any of them. Redis is the one place all instances agree on, and
 * its per-key TTL expires the window for free -- no sweeper job.
 *
 * Fixed window, not sliding: one INCR per request and nothing to clean up. The
 * known cost is a burst at the boundary -- a caller can spend a full window at
 * 11:59:59 and another at 12:00:00, briefly doing 2x the limit. A sliding window
 * log fixes that at the price of storing a timestamp per request. For login
 * endpoints, where the limit exists to make brute force slow rather than to meter
 * billing exactly, the simpler structure is the right trade.
 */

export interface RateLimitResult {
  limited: boolean;
  limit: number;
  remaining: number;
  /** Seconds until the window resets. */
  resetSeconds: number;
}

/**
 * INCR and EXPIRE in one round trip, as a Lua script.
 *
 * Done atomically because the two-command version has a real failure mode: if
 * the process dies between INCR and EXPIRE, the key is left with no TTL and that
 * caller is limited forever. Redis runs a script to completion without
 * interleaving other commands, so the key can never exist without its expiry.
 */
const INCREMENT_SCRIPT = `
  local current = redis.call('INCR', KEYS[1])
  if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
  end
  return { current, redis.call('TTL', KEYS[1]) }
`;

export interface RateLimitOptions {
  /** Namespace, so separate endpoints keep separate counters. */
  bucket: string;
  /** Who is being limited: an IP, an account, or a combination. */
  identifier: string;
  limit: number;
  windowSeconds: number;
}

export async function consumeRateLimit(options: RateLimitOptions): Promise<RateLimitResult> {
  const key = `ratelimit:${options.bucket}:${options.identifier}`;

  try {
    const [count, ttl] = (await redis.eval(
      INCREMENT_SCRIPT,
      1,
      key,
      String(options.windowSeconds),
    )) as [number, number];

    return {
      limited: count > options.limit,
      limit: options.limit,
      remaining: Math.max(0, options.limit - count),
      resetSeconds: ttl > 0 ? ttl : options.windowSeconds,
    };
  } catch (error) {
    // Fail OPEN: a Redis outage must not lock every user out of the service.
    //
    // This is a deliberate availability-over-security call, and it is only
    // defensible because of a second line of defence: /health/ready reports
    // Redis as down, so an orchestrator pulls the instance out of rotation
    // rather than leaving it serving unlimited login attempts indefinitely.
    logger.error({ err: error, bucket: options.bucket }, 'Rate limiter unavailable, failing open');

    return {
      limited: false,
      limit: options.limit,
      remaining: options.limit,
      resetSeconds: options.windowSeconds,
    };
  }
}

/** Clears a counter early -- used when a successful login should forgive earlier failures. */
export async function resetRateLimit(bucket: string, identifier: string): Promise<void> {
  try {
    await redis.del(`ratelimit:${bucket}:${identifier}`);
  } catch (error) {
    logger.error({ err: error, bucket }, 'Failed to reset rate limit counter');
  }
}
