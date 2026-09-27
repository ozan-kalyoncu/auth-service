import { prisma } from '../lib/prisma.js';
import { AppError } from '../lib/app-error.js';
import { logger } from '../lib/logger.js';
import type { OAuthProfile } from '../lib/oauth/client.js';
import type { ProviderName } from '../lib/oauth/providers.js';
import type { UserModel as User } from '../generated/prisma/models.js';

export type LinkOutcome = 'signed-in' | 'linked' | 'created';

export interface OAuthLoginResult {
  user: User;
  outcome: LinkOutcome;
}

/**
 * Resolves a provider profile to a local user, creating or linking as needed.
 *
 * Three cases, in priority order:
 *   1. this provider identity is already linked  -> sign that user in
 *   2. a local account exists with the same email -> link them together
 *   3. nothing matches                            -> create a new account
 *
 * Case 2 is the whole point of the OAuthAccount table: signing up with a
 * password and later clicking "Sign in with Google" must land on ONE account,
 * not two accounts quietly sharing an email address.
 */
export async function findOrCreateUserForProfile(
  provider: ProviderName,
  profile: OAuthProfile,
): Promise<OAuthLoginResult> {
  const email = profile.email.trim().toLowerCase();

  // 1. Known identity. Matched on the provider's stable user id, never on email:
  // people change their email address, and matching on one would hand the
  // account to whoever inherits that address next.
  const existingLink = await prisma.oAuthAccount.findUnique({
    where: {
      provider_providerUserId: { provider, providerUserId: profile.providerUserId },
    },
    include: { user: true },
  });

  if (existingLink) {
    return { user: existingLink.user, outcome: 'signed-in' };
  }

  const userWithSameEmail = await prisma.user.findUnique({ where: { email } });

  // 2. Link to the existing account -- but ONLY on a provider-verified address.
  //
  // This is the pre-account-takeover attack, and it is easy to get wrong: if we
  // linked on an unverified address, an attacker could create an account at a
  // sloppy provider using victim@example.com, sign in here, and be handed the
  // victim's existing account. An unverified email proves nothing about who
  // controls the mailbox.
  if (userWithSameEmail) {
    if (!profile.emailVerified) {
      logger.warn(
        { provider, userId: userWithSameEmail.id },
        'Refused to link OAuth identity with an unverified email',
      );

      throw AppError.forbidden(
        'That email is already registered here, and the provider has not verified it. ' +
          'Sign in with your password first, or verify the address with the provider.',
      );
    }

    await prisma.oAuthAccount.create({
      data: { provider, providerUserId: profile.providerUserId, userId: userWithSameEmail.id },
    });

    logger.info({ provider, userId: userWithSameEmail.id }, 'Linked OAuth identity to account');

    return { user: userWithSameEmail, outcome: 'linked' };
  }

  // 3. Brand new account.
  //
  // passwordHash stays null -- that is exactly why the column is nullable. The
  // alternative, inventing a random password nobody knows, would leave an
  // unusable credential on the account and make "does this user have a password?"
  // unanswerable.
  const created = await prisma.user.create({
    data: {
      email,
      passwordHash: null,
      // Trust the provider's verification rather than emailing our own link: the
      // user has already proven control of this mailbox to Google or GitHub.
      isEmailVerified: profile.emailVerified,
      oauthAccounts: {
        create: { provider, providerUserId: profile.providerUserId },
      },
    },
  });

  logger.info({ provider, userId: created.id }, 'Created account from OAuth sign-in');

  return { user: created, outcome: 'created' };
}

/** The providers already linked to an account, for display on a settings screen. */
export async function listLinkedProviders(userId: string): Promise<ProviderName[]> {
  const accounts = await prisma.oAuthAccount.findMany({
    where: { userId },
    select: { provider: true },
  });

  return accounts.map((account) => account.provider as ProviderName);
}
