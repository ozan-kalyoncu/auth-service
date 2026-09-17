import type { ErrorRequestHandler, RequestHandler } from 'express';
import { ZodError } from 'zod';
import { AppError } from '../lib/app-error.js';
import { ErrorCode } from '../config/constants.js';
import { logger } from '../lib/logger.js';
import { isProduction } from '../config/env.js';

/** Catch-all for unmatched routes, so a typo'd URL gets the same JSON shape as everything else. */
export const notFoundHandler: RequestHandler = (req, _res, next) => {
  next(AppError.notFound(`Route ${req.method} ${req.originalUrl} not found`));
};

/**
 * The single place any error becomes an HTTP response.
 *
 * Express recognises this as an error handler by its four arguments -- drop the
 * unused `next` and it silently becomes ordinary middleware that never runs.
 * It is registered LAST, after all routes, because Express walks the stack in
 * registration order looking for the first error handler past the failure point.
 */
export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  // Zod throws its own error type; translate it once here rather than wrapping
  // every validator call site in a try/catch.
  if (err instanceof ZodError) {
    res.status(400).json({
      error: {
        code: ErrorCode.VALIDATION_ERROR,
        message: 'Request validation failed',
        details: err.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      },
    });
    return;
  }

  if (err instanceof AppError) {
    // Expected, deliberate failures (bad password, expired token). They are normal
    // traffic, not incidents, so they log at warn/info rather than error.
    logger[err.statusCode >= 500 ? 'error' : 'warn'](
      { err, path: req.originalUrl, code: err.code },
      err.message,
    );

    res.status(err.statusCode).json({
      error: {
        code: err.code,
        message: err.message,
        ...(err.details !== undefined ? { details: err.details } : {}),
      },
    });
    return;
  }

  // Anything reaching here is an unhandled bug. Log it in full for us, but return
  // a generic message: stack traces and driver errors leak table names, query
  // shapes and file paths that help an attacker map the system.
  logger.error({ err, path: req.originalUrl }, 'Unhandled error');

  res.status(500).json({
    error: {
      code: ErrorCode.INTERNAL_ERROR,
      message: 'Internal server error',
      ...(isProduction ? {} : { details: err instanceof Error ? err.message : String(err) }),
    },
  });
};
