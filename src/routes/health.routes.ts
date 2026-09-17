import { Router } from 'express';
import { asyncHandler } from '../middleware/async-handler.js';
import { getLiveness, getReadiness } from '../controllers/health.controller.js';

export const healthRouter: Router = Router();

healthRouter.get('/live', getLiveness);
healthRouter.get('/ready', asyncHandler(getReadiness));
