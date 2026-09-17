import type { NextFunction, Request, RequestHandler, Response } from 'express';

/**
 * Wraps an async route handler so a rejected promise reaches the error handler.
 *
 * Express 4 only catches errors thrown SYNCHRONOUSLY. An `await` that rejects
 * inside a bare async handler produces an unhandled rejection and a request that
 * hangs until the client times out -- no response, no log. Wrapping in this
 * helper is what makes `throw AppError.unauthorized()` work inside async code.
 */
export function asyncHandler(
  handler: (req: Request, res: Response, next: NextFunction) => Promise<unknown>,
): RequestHandler {
  return (req, res, next) => {
    handler(req, res, next).catch(next);
  };
}
