import type { Request, Response } from 'express';
import { checkHealth } from '../services/health.service.js';

/**
 * Liveness: "is the process up?" Deliberately touches nothing external, so a
 * database outage does not make an orchestrator kill and restart a perfectly
 * healthy process -- restarting would not fix the database anyway.
 */
export function getLiveness(_req: Request, res: Response): void {
  res.status(200).json({ status: 'ok' });
}

/**
 * Readiness: "can this instance serve traffic right now?" This one does check
 * dependencies, and returns 503 when they are down so a load balancer takes the
 * instance out of rotation instead of sending it requests that will fail.
 */
export async function getReadiness(_req: Request, res: Response): Promise<void> {
  const report = await checkHealth();
  res.status(report.status === 'ok' ? 200 : 503).json(report);
}
