import 'dotenv/config';
import path from 'node:path';
import { defineConfig } from 'prisma/config';

/**
 * Prisma CLI configuration.
 *
 * Prisma 7 reads this file instead of the old `prisma` key in package.json. It
 * exists here mainly to point the CLI at src/prisma/schema.prisma, since this
 * project keeps the schema inside src/ alongside the code that uses it rather
 * than in Prisma's default top-level ./prisma directory.
 */
export default defineConfig({
  schema: path.join('src', 'prisma', 'schema.prisma'),
  migrations: {
    path: path.join('src', 'prisma', 'migrations'),
  },
  // Only the CLI (migrate, studio) uses this URL. The application gets its
  // connection from the driver adapter in src/lib/prisma.ts.
  datasource: {
    url: process.env.DATABASE_URL ?? '',
  },
});
