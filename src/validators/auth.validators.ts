import { z } from 'zod';
import { emailSchema, passwordSchema } from './common.js';

/**
 * Request schemas for the auth endpoints.
 *
 * Every schema is strict-by-omission: `validate` middleware replaces req.body
 * with the PARSED object, so any extra field a client sends is dropped before it
 * can reach a Prisma call. That is what stops a request like
 * `{ email, password, role: "SUPERADMIN" }` from ever mattering -- the role field
 * simply does not survive validation.
 */

export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
});

export const loginSchema = z.object({
  // Login deliberately uses a LOOSER password rule than registration: just
  // "a non-empty string". Applying the 12-character minimum here would reject a
  // short guess before checking it, telling an attacker that no account could
  // have that password -- and it would break existing users if the policy is
  // ever tightened.
  email: emailSchema,
  password: z.string().min(1, 'Password is required'),
});

export const verifyEmailQuerySchema = z.object({
  token: z.string().min(1, 'Verification token is required'),
});

export const resendVerificationSchema = z.object({
  email: emailSchema,
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
