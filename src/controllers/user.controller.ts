import type { Request, Response } from 'express';
import { findUserById, listUsers, toPublicUser } from '../services/user.service.js';
import { changeUserRole, removeUser } from '../services/user-admin.service.js';
import { requireUser } from '../middleware/authenticate.js';
import { AppError } from '../lib/app-error.js';
import type { ListUsersQuery, UpdateRoleInput } from '../validators/user.validators.js';

/**
 * Admin-facing user management. Every route reaching these handlers has already
 * passed authenticate + an authorization guard, so none of them re-check
 * permissions -- that is the point of doing it in middleware.
 */

export async function list(req: Request, res: Response): Promise<void> {
  const { limit, offset } = req.query as unknown as ListUsersQuery;

  const page = await listUsers({ limit, offset });

  res.status(200).json(page);
}

export async function getById(req: Request, res: Response): Promise<void> {
  const id = req.params.id as string;

  const user = await findUserById(id);

  if (!user) {
    throw AppError.notFound('User not found');
  }

  res.status(200).json({ user: toPublicUser(user) });
}

export async function updateRole(req: Request, res: Response): Promise<void> {
  const actor = requireUser(req);
  const { role } = req.body as UpdateRoleInput;

  const user = await changeUserRole(actor.id, req.params.id as string, role);

  res.status(200).json({ user });
}

export async function remove(req: Request, res: Response): Promise<void> {
  const actor = requireUser(req);

  await removeUser(actor.id, req.params.id as string);

  res.status(204).send();
}
