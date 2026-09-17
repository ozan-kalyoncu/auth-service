import { Router } from 'express';
import { healthRouter } from './health.routes.js';

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

// Mounted here as milestones land:
//   apiRouter.use('/auth', authRouter);   // milestones 2-3
//   apiRouter.use('/users', userRouter);  // milestone 4
