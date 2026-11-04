import { Router } from 'express';
import swaggerUi from 'swagger-ui-express';
import { healthRouter } from './health.routes.js';
import { authRouter } from './auth.routes.js';
import { userRouter } from './user.routes.js';
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
apiRouter.use('/users', userRouter);

// The machine-readable API contract, as plain JSON so it can be imported into
// Postman or Insomnia, or used to generate a typed client.
apiRouter.get('/openapi.json', (_req, res) => {
  res.status(200).json(openApiDocument);
});

// Swagger UI: an interactive page over the same document. The UI is told to
// fetch /openapi.json rather than having the spec inlined into its page, so the
// JSON endpoint stays the single source of truth -- and the page's script loads
// as a same-origin file, which Helmet's default Content-Security-Policy allows
// without loosening it for inline scripts.
apiRouter.use(
  '/docs',
  swaggerUi.serve,
  swaggerUi.setup(undefined, {
    customSiteTitle: 'Auth Service API',
    swaggerOptions: { url: '/api/v1/openapi.json' },
  }),
);

