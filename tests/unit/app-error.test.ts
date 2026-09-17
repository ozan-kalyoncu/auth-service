import { describe, expect, it } from 'vitest';
import { AppError } from '../../src/lib/app-error.js';
import { ErrorCode } from '../../src/config/constants.js';

describe('AppError', () => {
  it('maps each factory to the right status code and error code', () => {
    expect(AppError.badRequest('bad')).toMatchObject({
      statusCode: 400,
      code: ErrorCode.VALIDATION_ERROR,
    });
    expect(AppError.unauthorized()).toMatchObject({
      statusCode: 401,
      code: ErrorCode.UNAUTHORIZED,
    });
    expect(AppError.forbidden()).toMatchObject({ statusCode: 403, code: ErrorCode.FORBIDDEN });
    expect(AppError.notFound()).toMatchObject({ statusCode: 404, code: ErrorCode.NOT_FOUND });
    expect(AppError.conflict('taken')).toMatchObject({ statusCode: 409, code: ErrorCode.CONFLICT });
    expect(AppError.rateLimited()).toMatchObject({ statusCode: 429, code: ErrorCode.RATE_LIMITED });
    expect(AppError.internal()).toMatchObject({ statusCode: 500, code: ErrorCode.INTERNAL_ERROR });
  });

  it('is a real Error, so `throw` and instanceof both behave', () => {
    const error = AppError.forbidden('nope');

    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(AppError);
    expect(error.message).toBe('nope');
    expect(error.stack).toBeDefined();
  });

  it('carries optional details through untouched', () => {
    const details = [{ path: 'email', message: 'Required' }];

    expect(AppError.badRequest('invalid', details).details).toEqual(details);
    expect(AppError.badRequest('invalid').details).toBeUndefined();
  });
});
