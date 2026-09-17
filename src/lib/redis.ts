import { Redis } from 'ioredis';
import { env } from '../config/env.js';
import { logger } from './logger.js';

/**
 * Redis backs rate limiting and short-lived token state.
 *
 * Why not an in-memory Map? Because the moment this service runs as more than one
 * container (and any real deployment does), an in-memory counter is per-instance:
 * an attacker spreading 100 login attempts across 4 instances would see each
 * instance count only 25 and never trip the limit. Redis is the shared source of
 * truth all instances agree on, and its per-key TTLs expire counters for free.
 */
export const redis = new Redis(env.REDIS_URL, {
  // Fail a command rather than queueing it forever when Redis is down, so a Redis
  // outage surfaces as a fast error instead of requests hanging until timeout.
  maxRetriesPerRequest: 3,
  lazyConnect: true,
});

redis.on('error', (error: Error) => {
  logger.error({ err: error }, 'Redis connection error');
});

export async function connectRedis(): Promise<void> {
  // lazyConnect means the socket opens here, at startup, instead of on the first
  // command -- so a bad REDIS_URL fails at boot rather than mid-request.
  if (redis.status === 'ready' || redis.status === 'connecting') return;
  await redis.connect();
}

export async function disconnectRedis(): Promise<void> {
  await redis.quit();
}
