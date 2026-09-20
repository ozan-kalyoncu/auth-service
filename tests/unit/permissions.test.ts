import { describe, expect, it } from 'vitest';
import { Permission, permissionsForRole, roleHasPermission } from '../../src/config/permissions.js';
import { Role } from '../../src/generated/prisma/enums.js';

describe('role → permission mapping', () => {
  it('gives a plain user no administrative capability', () => {
    expect(permissionsForRole(Role.USER)).toEqual([]);
  });

  it('gives an admin read access but not role management or deletion', () => {
    expect(roleHasPermission(Role.ADMIN, Permission.USERS_READ)).toBe(true);
    expect(roleHasPermission(Role.ADMIN, Permission.USERS_MANAGE_ROLES)).toBe(false);
    expect(roleHasPermission(Role.ADMIN, Permission.USERS_DELETE)).toBe(false);
  });

  it('gives a superadmin everything an admin has, plus its own', () => {
    for (const permission of permissionsForRole(Role.ADMIN)) {
      expect(roleHasPermission(Role.SUPERADMIN, permission)).toBe(true);
    }

    expect(roleHasPermission(Role.SUPERADMIN, Permission.USERS_MANAGE_ROLES)).toBe(true);
    expect(roleHasPermission(Role.SUPERADMIN, Permission.USERS_DELETE)).toBe(true);
  });

  it('covers every role in the schema', () => {
    // Adding a role to the Prisma enum without granting it a permission set
    // would otherwise surface as `undefined.includes(...)` at request time.
    for (const role of Object.values(Role)) {
      expect(Array.isArray(permissionsForRole(role))).toBe(true);
    }
  });

  it('denies unknown permissions rather than defaulting to allow', () => {
    expect(roleHasPermission(Role.SUPERADMIN, 'billing:refund' as Permission)).toBe(false);
  });
});
