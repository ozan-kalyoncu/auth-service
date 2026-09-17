import type { Server } from 'node:http';
import { createApp } from './app.js';
import { env } from './config/env.js';
import { logger } from './lib/logger.js';
import { connectRedis, disconnectRedis } from './lib/redis.js';
import { disconnectPrisma, prisma } from './lib/prisma.js';

/**
 * Process entry point: connect dependencies, start listening, and shut down
 * cleanly. app.ts holds the HTTP wiring; everything lifecycle-related lives here.
 */
async function start(): Promise<void> {
  // Connect BEFORE listening. If Postgres or Redis is unreachable, the process
  // should die at boot with a clear error rather than accept traffic it cannot
  // serve and return 500s to real users.
  await prisma.$connect();
  await connectRedis();

  const app = createApp();
  const server = app.listen(env.PORT, () => {
    logger.info({ port: env.PORT, env: env.NODE_ENV }, 'auth-service listening');
  });

  registerShutdownHandlers(server);
}

/**
 * Graceful shutdown.
 *
 * Docker/Kubernetes send SIGTERM and then wait before sending SIGKILL. Without a
 * handler, the process dies instantly and any request being served is dropped
 * mid-flight. Here we stop accepting NEW connections, let in-flight requests
 * finish, then close the database and Redis connections.
 */
function registerShutdownHandlers(server: Server): void {
  let shuttingDown = false;

  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;

    logger.info({ signal }, 'Shutting down');

    // Safety net: if in-flight requests hang, exit anyway rather than blocking
    // the deploy until the orchestrator SIGKILLs us.
    const forceExit = setTimeout(() => {
      logger.error('Graceful shutdown timed out, forcing exit');
      process.exit(1);
    }, 10_000);
    forceExit.unref();

    server.close(async () => {
      try {
        await Promise.all([disconnectPrisma(), disconnectRedis()]);
        logger.info('Shutdown complete');
        process.exit(0);
      } catch (error) {
        logger.error({ err: error }, 'Error during shutdown');
        process.exit(1);
      }
    });
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  // An unhandled rejection leaves the process in an unknown state. Crashing loudly
  // (so the orchestrator restarts a clean one) beats limping along corrupted.
  process.on('unhandledRejection', (reason) => {
    logger.fatal({ err: reason }, 'Unhandled promise rejection');
    process.exit(1);
  });

  process.on('uncaughtException', (error) => {
    logger.fatal({ err: error }, 'Uncaught exception');
    process.exit(1);
  });
}

start().catch((error: unknown) => {
  logger.fatal({ err: error }, 'Failed to start auth-service');
  process.exit(1);
});
