import { prisma } from '../lib/prisma.js';
import { redis } from '../lib/redis.js';

export type DependencyStatus = 'up' | 'down';

export interface HealthReport {
  status: 'ok' | 'degraded';
  uptimeSeconds: number;
  dependencies: {
    database: DependencyStatus;
    redis: DependencyStatus;
  };
}

/**
 * Health checks actually TALK to each dependency instead of returning a constant.
 *
 * A health endpoint that always returns 200 tells an orchestrator nothing: the
 * process can be alive while its database connection is gone, and Kubernetes /
 * compose would happily keep routing traffic to it. Running a trivial query is
 * the cheapest way to distinguish "process running" from "service working".
 */
export async function checkHealth(): Promise<HealthReport> {
  const [database, cache] = await Promise.all([checkDatabase(), checkRedis()]);

  return {
    status: database === 'up' && cache === 'up' ? 'ok' : 'degraded',
    uptimeSeconds: Math.floor(process.uptime()),
    dependencies: { database, redis: cache },
  };
}

async function checkDatabase(): Promise<DependencyStatus> {
  try {
    await prisma.$queryRaw`SELECT 1`;
    return 'up';
  } catch {
    return 'down';
  }
}

async function checkRedis(): Promise<DependencyStatus> {
  try {
    const pong = await redis.ping();
    return pong === 'PONG' ? 'up' : 'down';
  } catch {
    return 'down';
  }
}
