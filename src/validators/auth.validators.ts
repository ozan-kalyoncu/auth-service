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

/**
 * Refresh and logout take an OPTIONAL refresh token in the body.
 *
 * Browsers send it automatically in the httpOnly cookie and post nothing at all,
 * so the body must be allowed to be empty. Non-browser clients (curl, another
 * service) have no cookie jar and pass it here instead. "Missing from both" is
 * a 401 decided in the controller, not a validation error -- absent credentials
 * are an auth failure, not a malformed request.
 */
export const refreshSchema = z.object({
  refreshToken: z.string().min(1).optional(),
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
