import type { RequestHandler } from 'express';
import type { ZodType } from 'zod';

interface RequestSchemas {
  body?: ZodType;
  query?: ZodType;
  params?: ZodType;
}

/**
 * Validates a request against Zod schemas BEFORE the controller runs.
 *
 * Two reasons this is middleware and not a call at the top of each controller:
 * the controller can then assume its input is already well-formed (no defensive
 * checks scattered through business logic), and validation becomes impossible to
 * forget on a new endpoint -- it is visible right there in the route definition.
 *
 * It also replaces req.body with the PARSED value, so unknown extra fields a
 * client sends are stripped rather than flowing into a Prisma call.
 */
export function validate(schemas: RequestSchemas): RequestHandler {
  return (req, _res, next) => {
    try {
      if (schemas.body) req.body = schemas.body.parse(req.body);
      if (schemas.params) req.params = schemas.params.parse(req.params) as typeof req.params;

      // req.query is a getter in newer Express versions, so we assign the parsed
      // result onto the existing object instead of replacing the property.
      if (schemas.query) {
        Object.assign(req.query, schemas.query.parse(req.query));
      }

      next();
    } catch (error) {
      // ZodError is translated into the standard error shape by errorHandler.
      next(error);
    }
  };
}
