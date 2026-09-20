import { describe, expect, it } from 'vitest';
import { generateSecureToken, hashToken, safeCompare } from '../../src/lib/crypto.js';
import { parseDurationToSeconds } from '../../src/services/token.service.js';

describe('generateSecureToken', () => {
  it('produces URL-safe tokens that never repeat', () => {
    const tokens = new Set(Array.from({ length: 500 }, () => generateSecureToken()));

    expect(tokens.size).toBe(500);
    for (const token of tokens) {
      // base64url: safe to drop into a query string without escaping.
      expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    }
  });
});

describe('hashToken', () => {
  it('is deterministic and one-way', () => {
    const token = generateSecureToken();

    expect(hashToken(token)).toBe(hashToken(token));
    expect(hashToken(token)).toMatch(/^[a-f0-9]{64}$/);
    expect(hashToken(token)).not.toContain(token);
  });
});

describe('safeCompare', () => {
  it('matches equal strings and rejects differing or differently-sized ones', () => {
    expect(safeCompare('abc123', 'abc123')).toBe(true);
    expect(safeCompare('abc123', 'abc124')).toBe(false);
    // Length mismatch must return false rather than throwing.
    expect(safeCompare('abc', 'abcdef')).toBe(false);
  });
});

describe('parseDurationToSeconds', () => {
  it('converts the duration strings used in config', () => {
    expect(parseDurationToSeconds('30s')).toBe(30);
    expect(parseDurationToSeconds('15m')).toBe(900);
    expect(parseDurationToSeconds('2h')).toBe(7200);
    expect(parseDurationToSeconds('7d')).toBe(604800);
  });

  it('treats a bare number as seconds, like jsonwebtoken does', () => {
    expect(parseDurationToSeconds('600')).toBe(600);
  });

  it('throws on a value it cannot interpret', () => {
    expect(() => parseDurationToSeconds('fortnight')).toThrow();
  });
});
