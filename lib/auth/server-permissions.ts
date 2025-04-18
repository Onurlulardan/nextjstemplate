'use server';

import { getServerSession } from 'next-auth';
import { authOptions } from './auth-options';
import { redirect } from 'next/navigation';
import { OrganizationMembership, Permission } from './types';

/**
 * Checks if a permission object allows a specific action
 * @param permission - The permission object to check
 * @param actionSlug - The action slug to check for
 * @returns True if the permission allows the specified action, false otherwise
 */
function hasActionPermission(permission: Permission, actionSlug: string): boolean {
  return permission.actions.some((a) => a.slug === actionSlug || a.slug === 'manage');
}

/**
 * Checks permissions for a specific resource and action
 * @param permissions - List of permissions to check
 * @param resourceSlug - The resource slug to check
 * @param actionSlug - The action slug to check
 * @returns True if permission exists for the specified resource and action, false otherwise
 */
function checkResourcePermission(
  permissions: Permission[],
  resourceSlug: string,
  actionSlug: string
): boolean {
  return permissions.some(
    (p) =>
      // Check for specific resource permission
      (p.resource.slug === resourceSlug || p.resource.slug === '*') &&
      hasActionPermission(p, actionSlug)
  );
}

/**
 * Checks if the user has permission for a specific resource and action on the server side
 * @param resourceSlug - The resource slug to check (e.g., 'user', 'role', 'organization')
 * @param actionSlug - The action slug to check (e.g., 'create', 'view', 'edit', 'delete')
 * @param organizationId - Optional, used to check permissions for a specific organization
 * @returns True if the user has permission for the specified resource and action, false otherwise
 * @example
 * // Check if the user has permission to create a role
 * const canCreateRole = await checkPermission('role', 'create');
 * 
 * // Check if the user has permission to edit a user in a specific organization
 * const canEditUser = await checkPermission('user', 'edit', 'org-123');
 */
export async function checkPermission(
  resourceSlug: string,
  actionSlug: string,
  organizationId?: string
): Promise<boolean> {
  const session = await getServerSession(authOptions);
  if (!session) return false;

  // System admin can do anything
  // Check if user has ADMIN role
  const hasAdminRole = session.user.userRoles?.some((ur: { role: { name: string } }) => ur.role.name === 'ADMIN');
  if (hasAdminRole) return true;

  // Check user's direct permissions
  const hasDirectPermission = checkResourcePermission(
    session.user.permissions,
    resourceSlug,
    actionSlug
  );

  if (hasDirectPermission) return true;

  // If organizationId is provided, check organization permissions
  if (organizationId) {
    const membership = session.user.memberships.find(
      (m: OrganizationMembership) => m.organization.id === organizationId
    );

    if (!membership) return false;

    // Check role-based permissions
    const rolePermissions = membership.role?.permissions || [];
    const hasRolePermission = checkResourcePermission(rolePermissions, resourceSlug, actionSlug);

    if (hasRolePermission) return true;

    // Check organization-level permissions
    const organizationPermissions = membership.organization.permissions;
    return checkResourcePermission(organizationPermissions, resourceSlug, actionSlug);
  }

  // If no organizationId is provided, check permissions across all organizations
  return session.user.memberships.some((membership: OrganizationMembership) => {
    // Check role-based permissions
    const rolePermissions = membership.role?.permissions || [];
    const hasRolePermission = checkResourcePermission(rolePermissions, resourceSlug, actionSlug);

    if (hasRolePermission) return true;

    // Check organization-level permissions
    return checkResourcePermission(membership.organization.permissions, resourceSlug, actionSlug);
  });
}

/**
 * Checks if the user has permission for a specific resource and action on the server side
 * and redirects to the unauthorized page if not
 * @param resourceSlug - The resource slug to check (e.g., 'user', 'role', 'organization')
 * @param actionSlug - The action slug to check (e.g., 'create', 'view', 'edit', 'delete')
 * @param organizationId - Optional, used to check permissions for a specific organization
 * @returns Promise<void> if the user has permission, otherwise redirects to the unauthorized page
 * @example
 * // Usage in an API route:
 * export async function GET(request: NextRequest) {
 *   try {
 *     // Check if the user has permission to view roles
 *     await requirePermission('role', 'view');
 *     
 *     // If permission exists, continue with the API operation
 *     // ...
 *   } catch (error) {
 *     // Error handling
 *   }
 * }
 */
export async function requirePermission(
  resourceSlug: string,
  actionSlug: string,
  organizationId?: string
): Promise<void> {
  const hasPermission = await checkPermission(resourceSlug, actionSlug, organizationId);
  if (!hasPermission) {
    redirect('/auth/unauthorized');
  }
}
