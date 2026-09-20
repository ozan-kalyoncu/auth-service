import { prisma, disconnectPrisma } from '../lib/prisma.js';
import { revokeAllUserTokens } from '../services/refresh-token.service.js';
import { Role } from '../generated/prisma/enums.js';

/**
 * Promotes or demotes a user from the command line.
 *
 *   npm run set-role -- user@example.com ADMIN
 *
 * In a container, run the compiled form instead -- the runtime image installs
 * production dependencies only, so tsx is not available there:
 *
 *   docker compose exec app node dist/scripts/set-role.js user@example.com ADMIN
 *
 * This exists because of a bootstrapping problem: changing a role requires the
 * users:manage-roles permission, which only a SUPERADMIN has, and a fresh
 * database contains no SUPERADMIN. Something outside the HTTP API has to create
 * the first one. Deliberately a manual operator action rather than a seed that
 * runs on startup -- an auto-created admin account with a known email is a
 * backdoor in every environment it reaches.
 */
async function main(): Promise<void> {
  const [email, roleArg] = process.argv.slice(2);

  if (!email || !roleArg) {
    console.error('Usage: npm run set-role -- <email> <USER|ADMIN|SUPERADMIN>');
    process.exitCode = 1;
    return;
  }

  const role = roleArg.toUpperCase();

  if (!Object.values(Role).includes(role as Role)) {
    console.error(`Invalid role "${roleArg}". Expected one of: ${Object.values(Role).join(', ')}`);
    process.exitCode = 1;
    return;
  }

  const user = await prisma.user.findUnique({ where: { email: email.trim().toLowerCase() } });

  if (!user) {
    console.error(`No user found with email ${email}`);
    process.exitCode = 1;
    return;
  }

  const updated = await prisma.user.update({
    where: { id: user.id },
    data: { role: role as Role },
  });

  // Same reasoning as the API path: the old role is baked into any access token
  // already issued, so end their sessions to stop those being renewed.
  const sessionsRevoked = await revokeAllUserTokens(user.id);

  console.log(
    `${updated.email}: ${user.role} -> ${updated.role} (${sessionsRevoked} session(s) revoked)`,
  );
}

main()
  .catch((error: unknown) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => {
    void disconnectPrisma();
  });
