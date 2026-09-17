import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../generated/prisma/client.js';
import { env, isProduction } from '../config/env.js';

/**
 * Prisma 7 talks to Postgres through a "driver adapter" -- here the standard
 * `pg` driver -- instead of a bundled query engine binary. Practically that means
 * the connection pool is a normal node-postgres pool we configure ourselves.
 */
const adapter = new PrismaPg({
  connectionString: env.DATABASE_URL,

  // Pool size is a real trade-off: every connection costs memory on the Postgres
  // side, and `max` is per application instance -- 10 connections times 5
  // containers is 50 against Postgres' default limit of 100. Raise it only with
  // the server's max_connections in mind.
  max: 10,

  // Drop idle connections so a traffic spike does not leave the pool holding
  // connections other instances could be using.
  idleTimeoutMillis: 30_000,
});

/**
 * A single shared PrismaClient for the whole process.
 *
 * Constructing one per request would create a new connection pool per request
 * and exhaust Postgres' connection limit within seconds -- one of the classic
 * ways a Node service falls over under load.
 */
export const prisma = new PrismaClient({
  adapter,
  log: isProduction ? ['error'] : ['warn', 'error'],
});

export async function disconnectPrisma(): Promise<void> {
  await prisma.$disconnect();
}
