import { prisma } from '../lib/prisma.js';
import { hashPassword } from '../lib/password.js';
// Prisma 7's client generator names the plain row type `<Model>Model`; aliased
// here so the rest of the code reads as `User`.
import type { UserModel as User } from '../generated/prisma/models.js';
import type { Role } from '../generated/prisma/enums.js';

/**
 * The shape of a user that is safe to return over the API.
 *
 * Defined explicitly rather than returning the Prisma `User` row, because that
 * row contains `passwordHash`. Serialising a whole database record into a
 * response is how password hashes end up in JSON -- the fix is to make the safe
 * shape the default and the full row the exception.
 */
export interface PublicUser {
  id: string;
  email: string;
  role: Role;
  isEmailVerified: boolean;
  createdAt: Date;
}

export function toPublicUser(user: User): PublicUser {
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    isEmailVerified: user.isEmailVerified,
    createdAt: user.createdAt,
  };
}

export function findUserByEmail(email: string): Promise<User | null> {
  // Emails are normalised to lowercase by the validator before they reach here,
  // so a plain equality lookup hits the unique index.
  return prisma.user.findUnique({ where: { email } });
}

export function findUserById(id: string): Promise<User | null> {
  return prisma.user.findUnique({ where: { id } });
}

export async function createUserWithPassword(email: string, password: string): Promise<User> {
  // Hash before the insert: the plaintext password never reaches the database
  // layer at all, so it cannot be caught by query logging.
  const passwordHash = await hashPassword(password);

  return prisma.user.create({
    data: { email, passwordHash },
  });
}

export function markEmailVerified(userId: string): Promise<User> {
  return prisma.user.update({
    where: { id: userId },
    data: { isEmailVerified: true },
  });
}

export interface ListUsersOptions {
  limit: number;
  offset: number;
}

export interface UserPage {
  users: PublicUser[];
  total: number;
  limit: number;
  offset: number;
}

/**
 * Lists users for the admin endpoints.
 *
 * Paginated with a hard ceiling on `limit` (enforced by the validator), because
 * an unbounded list endpoint is a denial-of-service waiting to happen: one
 * request for every row loads the whole table into memory and serialises it.
 * The total is returned alongside so a client can render page counts without a
 * second call.
 */
export async function listUsers(options: ListUsersOptions): Promise<UserPage> {
  const [users, total] = await Promise.all([
    prisma.user.findMany({
      orderBy: { createdAt: 'desc' },
      take: options.limit,
      skip: options.offset,
    }),
    prisma.user.count(),
  ]);

  return {
    users: users.map(toPublicUser),
    total,
    limit: options.limit,
    offset: options.offset,
  };
}

export function updateUserRole(userId: string, role: Role): Promise<User> {
  return prisma.user.update({ where: { id: userId }, data: { role } });
}

/**
 * Deletes a user.
 *
 * Their refresh tokens and OAuth links go with them: the schema declares
 * `onDelete: Cascade`, so the database removes those rows in the same statement
 * rather than leaving orphans behind if application code forgets. LoginAttempt
 * rows use SetNull instead -- the audit trail of a deleted account is still
 * worth keeping.
 */
export function deleteUser(userId: string): Promise<User> {
  return prisma.user.delete({ where: { id: userId } });
}
