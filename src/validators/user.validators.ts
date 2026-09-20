import { z } from 'zod';
import { cuidSchema } from './common.js';
import { Role } from '../generated/prisma/enums.js';

export const userIdParamSchema = z.object({
  id: cuidSchema,
});

/**
 * Pagination for the user list.
 *
 * `limit` is capped at 100 in the schema rather than trusted from the query
 * string. Without a ceiling, `?limit=1000000` is a one-request denial of
 * service: the database loads every row and the process serialises them all.
 * Query values arrive as strings, hence `coerce`.
 */
export const listUsersQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  offset: z.coerce.number().int().min(0).default(0),
});

/**
 * Validating the role against the enum matters more than it looks: without it,
 * an arbitrary string would reach Prisma and fail as a 500 database error rather
 * than a clear 400 naming the allowed values.
 */
export const updateRoleSchema = z.object({
  role: z.enum(Role),
});

export type ListUsersQuery = z.infer<typeof listUsersQuerySchema>;
export type UpdateRoleInput = z.infer<typeof updateRoleSchema>;
