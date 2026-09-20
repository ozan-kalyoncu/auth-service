import { Role } from '../generated/prisma/enums.js';

/**
 * Authorization is expressed in PERMISSIONS, not roles.
 *
 * The tempting shortcut is to scatter `if (user.role === 'ADMIN')` through the
 * code. It works until the fourth role arrives -- then "who may list users?"
 * has to be re-answered at every one of those sites, and the answer is only
 * discoverable by grepping. Naming the capability instead ("users:read") means a
 * route declares WHAT it needs, and the role→capability mapping lives in exactly
 * one table, right here.
 *
 * Scaling past these three roles: this map is static because a static map is
 * enough today and costs no query. Moving to fully dynamic roles means replacing
 * `permissionsForRole` with a lookup over Role/Permission/RolePermission tables
 * (cached per request). Every call site keeps asking "does this actor have
 * users:read?", so nothing outside this file changes -- which is the point of
 * routing all checks through one function now, before there is a reason to.
 */
export const Permission = {
  /** Read any user's record, not just your own. */
  USERS_READ: 'users:read',
  /** Change a user's role. */
  USERS_MANAGE_ROLES: 'users:manage-roles',
  /** Delete a user account. */
  USERS_DELETE: 'users:delete',
} as const;

export type Permission = (typeof Permission)[keyof typeof Permission];

/**
 * Permissions granted to each role.
 *
 * Higher roles are built by spreading the lower one, so the inheritance is
 * literal and visible rather than implied by a comparison like `role >= ADMIN`.
 * Ordering roles numerically looks convenient right up to the first role that is
 * not more powerful, just different -- a support agent who may read users but
 * never delete one does not fit anywhere on a line.
 */
const USER_PERMISSIONS: readonly Permission[] = [];

const ADMIN_PERMISSIONS: readonly Permission[] = [...USER_PERMISSIONS, Permission.USERS_READ];

const SUPERADMIN_PERMISSIONS: readonly Permission[] = [
  ...ADMIN_PERMISSIONS,
  Permission.USERS_MANAGE_ROLES,
  Permission.USERS_DELETE,
];

const ROLE_PERMISSIONS: Record<Role, readonly Permission[]> = {
  [Role.USER]: USER_PERMISSIONS,
  [Role.ADMIN]: ADMIN_PERMISSIONS,
  [Role.SUPERADMIN]: SUPERADMIN_PERMISSIONS,
};

export function permissionsForRole(role: Role): readonly Permission[] {
  return ROLE_PERMISSIONS[role];
}

export function roleHasPermission(role: Role, permission: Permission): boolean {
  return permissionsForRole(role).includes(permission);
}
