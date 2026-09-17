import { pino } from 'pino';
import { env, isProduction, isTest } from '../config/env.js';

/**
 * Structured (JSON) logging rather than console.log.
 *
 * In production, logs are consumed by a machine -- a log aggregator that indexes
 * fields. `logger.info({ userId }, 'login succeeded')` is queryable by userId;
 * a formatted string is not. In development, pino-pretty would be nicer to read,
 * but it is an extra dependency, so we keep raw JSON here.
 */
export const logger = pino({
  level: isTest ? 'silent' : env.LOG_LEVEL,

  // Never let a secret reach the log store. Redaction happens at the logger, not
  // at each call site, because one forgotten call site is all it takes.
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'res.headers["set-cookie"]',
      '*.password',
      '*.passwordHash',
      '*.token',
      '*.refreshToken',
      '*.accessToken',
    ],
    censor: '[redacted]',
  },

  base: isProduction ? { service: 'auth-service' } : {},
});
