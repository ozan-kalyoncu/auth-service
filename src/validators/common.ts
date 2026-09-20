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
 * increases it exponentially. Current NIST guidance says to require length and
 * drop the composition rules, which is what this does.
 *
 * The upper bound is not cosmetic: Argon2 hashing is intentionally slow and
 * memory-hungry, so an unbounded password body turns the hash itself into a DoS
 * vector. (Argon2 has no inherent input limit -- bcrypt's famous 72-byte
 * truncation does not apply here -- so 128 is our choice, not the algorithm's.)
 */
export const passwordSchema = z
  .string()
  .min(12, 'Password must be at least 12 characters')
  .max(128, 'Password must be at most 128 characters');

/** cuid() is what every model's primary key uses, so route params are checked against it. */
export const cuidSchema = z.cuid('Must be a valid id');
