import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Generates a cryptographically random, URL-safe token.
 *
 * `randomBytes` comes from the OS entropy source. `Math.random()` is the wrong
 * tool here and always will be: it is a fast, predictable PRNG -- given a few
 * outputs its internal state can be reconstructed and every future "random"
 * token predicted. Fine for shuffling an array, catastrophic for a credential.
 *
 * 32 bytes = 256 bits of entropy, far past the point where guessing is feasible.
 */
export function generateSecureToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/**
 * SHA-256, returned as hex. Used to hash tokens before they are stored.
 *
 * Note the deliberate difference from passwords: this is a FAST hash, and that is
 * correct here. Slow hashing (Argon2) exists to make low-entropy human passwords
 * expensive to guess. A 256-bit random token has nothing to guess -- brute force
 * is already impossible -- so all that is needed is a one-way function that makes
 * a stolen database dump useless for replaying tokens. Argon2 on every token
 * lookup would add real latency and buy nothing.
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Compares two hex digests without leaking, through timing, how many characters
 * matched before the first difference.
 *
 * `a === b` exits at the first differing byte, so an attacker able to measure
 * response times can, in principle, recover a secret one character at a time.
 * timingSafeEqual always compares the full length.
 */
export function safeCompare(a: string, b: string): boolean {
  const bufferA = Buffer.from(a, 'utf8');
  const bufferB = Buffer.from(b, 'utf8');

  // timingSafeEqual throws on length mismatch, which would itself leak length.
  // Different lengths cannot be equal anyway, so return early on that.
  if (bufferA.length !== bufferB.length) return false;

  return timingSafeEqual(bufferA, bufferB);
}
