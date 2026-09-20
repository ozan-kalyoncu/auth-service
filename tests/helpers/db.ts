import { prisma } from '../../src/lib/prisma.js';
import { redis } from '../../src/lib/redis.js';

/**
 * Wipes all data between tests.
 *
 * TRUNCATE rather than deleting per table in dependency order: it is one
 * statement, it resets the tables together, and CASCADE handles the foreign keys
 * (LoginAttempt and RefreshToken both reference User).
 *
 * Tests get a clean database rather than sharing fixtures, so a failure points at
 * the test that failed instead of at whatever ran before it.
 */
export async function resetDatabase(): Promise<void> {
  await prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "LoginAttempt", "RefreshToken", "OAuthAccount", "User" RESTART IDENTITY CASCADE',
  );

  // Verification tokens live in Redis, so state there has to be cleared too --
  // otherwise a token minted in one test could still be redeemable in the next.
  await redis.flushdb();
}

export async function closeConnections(): Promise<void> {
  await Promise.allSettled([prisma.$disconnect(), redis.quit()]);
}
