import express, { type Express } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { pinoHttp } from 'pino-http';
import { env, isTest } from './config/env.js';
import { logger } from './lib/logger.js';
import { apiRouter } from './routes/index.js';
import { errorHandler, notFoundHandler } from './middleware/error-handler.js';
import { AppError } from './lib/app-error.js';

/**
 * Builds the Express app WITHOUT starting a server.
 *
 * Keeping app.ts (wiring) separate from server.ts (listening) is what lets
 * integration tests pass this app straight to Supertest -- no real port, no
 * port-in-use flakiness, no cleanup between test files.
 *
 * Middleware order below is deliberate: Express runs the stack top to bottom,
 * so anything that must apply to every request has to be registered before the
 * routes, and the error handler has to come last.
 */
export function createApp(): Express {
  const app = express();

  // Behind a reverse proxy (nginx, a load balancer), req.ip would otherwise be
  // the proxy's address -- which would make per-IP rate limiting count every user
  // as the same "IP". This makes Express read X-Forwarded-For instead.
  app.set('trust proxy', 1);

  // Removes the X-Powered-By: Express header. Minor, but there is no reason to
  // advertise the framework and version to someone scanning for known CVEs.
  app.disable('x-powered-by');

  // Helmet sets a bundle of defensive response headers (HSTS, X-Content-Type-
  // Options, frame denial, and so on). It is first so the headers are present
  // even on responses produced by the error handler.
  app.use(helmet());

  app.use(
    cors({
      // Browsers only allow cookies on cross-origin requests when the server
      // echoes back a specific origin -- "*" plus credentials is rejected. Hence
      // an explicit allowlist from config rather than a wildcard.
      origin(origin, callback) {
        // No Origin header = a non-browser client (curl, another service). CORS
        // is a browser-enforced policy, so there is nothing to enforce here.
        if (!origin) return callback(null, true);
        if (env.CORS_ORIGINS.includes(origin)) return callback(null, true);
        return callback(AppError.forbidden(`Origin ${origin} is not allowed`));
      },
      credentials: true,
    }),
  );

  // A body size cap is basic DoS protection: without it a single request can ask
  // the process to buffer an arbitrarily large JSON payload into memory. Auth
  // payloads are a few hundred bytes, so 100kb is generous.
  app.use(express.json({ limit: '100kb' }));
  app.use(express.urlencoded({ extended: true, limit: '100kb' }));

  // Refresh tokens arrive as httpOnly cookies, which means something has to parse
  // the Cookie header before the auth routes can read them.
  app.use(cookieParser());

  if (!isTest) {
    // One structured log line per request, with a generated request id that ties
    // every log line from the same request together.
    app.use(pinoHttp({ logger }));
  }

  app.use('/api/v1', apiRouter);

  // 404 first, then the error handler: an unmatched route becomes an AppError,
  // which the handler below formats like every other failure.
  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
