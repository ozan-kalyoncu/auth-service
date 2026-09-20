import { describe, expect, it } from 'vitest';
import { hashPassword, verifyPassword } from '../../src/lib/password.js';

describe('password hashing', () => {
  it('verifies a correct password and rejects a wrong one', async () => {
    const hash = await hashPassword('correct-horse-battery-staple');

    await expect(verifyPassword(hash, 'correct-horse-battery-staple')).resolves.toBe(true);
    await expect(verifyPassword(hash, 'correct-horse-battery-stapl')).resolves.toBe(false);
  });

  it('produces a different hash each time for the same password', async () => {
    const [first, second] = await Promise.all([
      hashPassword('same-password-twice-over'),
      hashPassword('same-password-twice-over'),
    ]);

    // Different random salts. This is what stops an attacker spotting that two
    // users share a password, and makes precomputed rainbow tables useless.
    expect(first).not.toBe(second);
    await expect(verifyPassword(first, 'same-password-twice-over')).resolves.toBe(true);
    await expect(verifyPassword(second, 'same-password-twice-over')).resolves.toBe(true);
  });

  it('embeds the argon2id parameters in the hash string', async () => {
    const hash = await hashPassword('parameters-are-embedded');

    // Storing the parameters alongside the hash is what lets them be tuned
    // upward later without invalidating every existing password.
    expect(hash).toMatch(/^\$argon2id\$v=19\$m=19456,p=1,t=2\$/);
  });

  it('returns false for a corrupt hash instead of throwing', async () => {
    await expect(verifyPassword('not-a-valid-hash', 'anything')).resolves.toBe(false);
  });
});
