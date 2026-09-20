import argon2 from 'argon2';

/**
 * Password hashing with Argon2id.
 *
 * A password hash is NOT meant to be fast. A fast hash (SHA-256, MD5) lets an
 * attacker who steals the database try billions of guesses per second on a GPU.
 * Argon2id is deliberately slow AND memory-hungry, which is the part that hurts
 * GPUs: they have thousands of cores but not gigabytes of memory per core.
 *
 * Argon2id won the Password Hashing Competition and is the current OWASP first
 * choice; it combines Argon2i's resistance to side-channel attacks with
 * Argon2d's resistance to GPU cracking.
 */
const HASH_OPTIONS = {
  type: argon2.argon2id,

  // ~19 MiB of memory per hash. This is the main defence against parallel
  // cracking, and the main cost to us: it is memory held for the duration of
  // every login. Raising it hardens hashes but lowers how many logins this
  // service can process at once -- the classic security/performance trade-off.
  memoryCost: 19456,

  // Passes over memory. 2 is the OWASP-recommended companion to 19 MiB.
  timeCost: 2,

  // Lanes of parallelism. 1 keeps CPU usage per hash predictable under load.
  parallelism: 1,
} as const;

/**
 * Hashes a plaintext password.
 *
 * Argon2 generates a random salt per call and embeds it -- along with the
 * parameters above -- in the returned string. That is why no salt column exists
 * in the schema, and why two identical passwords produce different hashes:
 * an attacker cannot tell that two users share a password, and precomputed
 * rainbow tables are useless.
 */
export function hashPassword(plaintext: string): Promise<string> {
  return argon2.hash(plaintext, HASH_OPTIONS);
}

/**
 * Verifies a password against a stored hash.
 *
 * The parameters are read back out of the hash string itself, so hashes created
 * with older settings keep verifying after HASH_OPTIONS is tuned upward.
 */
export async function verifyPassword(hash: string, plaintext: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, plaintext);
  } catch {
    // A malformed or truncated hash throws rather than returning false. Treat it
    // as "does not match" -- a corrupt hash must never authenticate anyone.
    return false;
  }
}

/**
 * A pre-computed hash of a throwaway password, used when logging in as an email
 * that does not exist.
 *
 * Without this, a failed login for an unknown email returns in microseconds
 * while a wrong password for a REAL email takes ~50ms of Argon2 work. That
 * timing gap is a user-enumeration oracle: an attacker can discover which email
 * addresses have accounts without ever guessing a password. Verifying against
 * this dummy hash makes both paths cost the same.
 */
let dummyHashPromise: Promise<string> | undefined;

export async function burnPasswordVerification(plaintext: string): Promise<void> {
  // Computed once per process, lazily, so startup is not delayed by it.
  dummyHashPromise ??= hashPassword('dummy-password-for-constant-time-login');
  await verifyPassword(await dummyHashPromise, plaintext);
}
