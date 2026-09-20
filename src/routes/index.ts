import { Router } from 'express';
import { healthRouter } from './health.routes.js';
import { authRouter } from './auth.routes.js';
import { openApiDocument } from '../docs/openapi.js';

/**
 * Every route is mounted under a version prefix (/api/v1) from day one.
 *
 * Other services will hold long-lived integrations against this API. When a
 * breaking change becomes necessary, /api/v2 can ship alongside v1 instead of
 * forcing every consumer to redeploy on the same day. Retrofitting versioning
 * after clients exist is far more painful than starting with it.
 */
export const apiRouter: Router = Router();

apiRouter.use('/health', healthRouter);
apiRouter.use('/auth', authRouter);

// The machine-readable API contract. Served as plain JSON for now so it can be
// imported into Postman or Insomnia; milestone 7 renders it with Swagger UI.
apiRouter.get('/openapi.json', (_req, res) => {
  res.status(200).json(openApiDocument);
});

// Mounted here as milestones land:
//   apiRouter.use('/users', userRouter);  // milestone 4
