import { Router } from 'express';
import { asyncHandler } from '../middleware/async-handler.js';
import { authenticate } from '../middleware/authenticate.js';
import * as oauthController from '../controllers/oauth.controller.js';

/**
 * OAuth2 routes, mounted under /api/v1/auth/oauth.
 *
 * These are browser endpoints rather than API endpoints: /:provider is what a
 * "Sign in with Google" link points at, and /:provider/callback is where Google
 * sends the user back. Neither is called by JavaScript, which is why they use
 * redirects and cookies rather than JSON bodies and bearer tokens.
 *
 * No `validate` middleware here: the query string is supplied by the provider,
 * not the client, and each field is checked in the controller as part of the
 * flow's own logic -- a missing `state` is an auth failure, not a 400.
 */
export const oauthRouter: Router = Router();

oauthRouter.get('/', oauthController.listProviders);

// Which providers the CALLER has linked, as opposed to which the server offers.
oauthRouter.get('/linked', authenticate, asyncHandler(oauthController.listMyLinkedProviders));

oauthRouter.get('/:provider', asyncHandler(oauthController.start));
oauthRouter.get('/:provider/callback', asyncHandler(oauthController.callback));
