import { z } from 'zod';

/**
 * Building blocks shared by the auth validators (milestone 2 onwards).
 * Defined once here so "what counts as a valid password" has exactly one answer.
 */

export const emailSchema = z
  .email('Must be a valid email address')
  // Stored and compared lowercase so Alice@x.com and alice@x.com cannot become two
  // accounts -- which would quietly break account linking and email verification.
  .transform((value) => value.trim().toLowerCase());

/**
 * Password rules: length is the requirement that actually matters.
 *
 * Composition rules ("must contain a symbol") push people toward predictable
 * patterns like `Password1!` while barely increasing the search space; length
 * increases it exponentially. The upper bound is not cosmetic either -- bcrypt
 * silently truncates at 72 bytes, and unbounded input makes the hash itself a
 * DoS vector, since hashing is intentionally slow.
 */
export const passwordSchema = z
  .string()
  .min(12, 'Password must be at least 12 characters')
  .max(72, 'Password must be at most 72 characters');

/** cuid() is what every model's primary key uses, so route params are checked against it. */
export const cuidSchema = z.cuid('Must be a valid id');
