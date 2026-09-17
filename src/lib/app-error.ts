import { ErrorCode } from '../config/constants.js';

/**
 * The one error type controllers and services throw on purpose.
 *
 * Why a class instead of returning `{ ok: false }` everywhere: a thrown AppError
 * unwinds straight to the central error handler, which is the single place that
 * decides status code and response shape. Controllers stay free of response
 * formatting, and any error that is NOT an AppError is by definition a bug --
 * the handler can safely treat it as a 500 and hide its details from the client.
 */
export class AppError extends Error {
  readonly statusCode: number;
  readonly code: ErrorCode;
  readonly details: unknown;

  constructor(statusCode: number, code: ErrorCode, message: string, details?: unknown) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;

    // Keeps the stack trace pointing at the throw site rather than this constructor.
    Error.captureStackTrace(this, AppError);
  }

  static badRequest(message: string, details?: unknown): AppError {
    return new AppError(400, ErrorCode.VALIDATION_ERROR, message, details);
  }

  static unauthorized(message = 'Authentication required'): AppError {
    return new AppError(401, ErrorCode.UNAUTHORIZED, message);
  }

  static forbidden(message = 'Insufficient permissions'): AppError {
    return new AppError(403, ErrorCode.FORBIDDEN, message);
  }

  static notFound(message = 'Resource not found'): AppError {
    return new AppError(404, ErrorCode.NOT_FOUND, message);
  }

  static conflict(message: string): AppError {
    return new AppError(409, ErrorCode.CONFLICT, message);
  }

  static rateLimited(message = 'Too many requests'): AppError {
    return new AppError(429, ErrorCode.RATE_LIMITED, message);
  }

  static internal(message = 'Internal server error'): AppError {
    return new AppError(500, ErrorCode.INTERNAL_ERROR, message);
  }
}
