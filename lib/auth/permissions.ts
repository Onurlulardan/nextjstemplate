import { getServerSession } from 'next-auth';
import { useSession } from 'next-auth/react';
import { authOptions } from './auth-options';
import { redirect } from 'next/navigation';
import { OrganizationMembership, Permission } from './types';
import React from 'react';

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

/**
 * React hook that checks if the user has permission for a specific resource and action on the client side
 * @param resourceSlug - The resource slug to check (e.g., 'user', 'role', 'organization')
 * @param actionSlug - The action slug to check (e.g., 'create', 'view', 'edit', 'delete')
 * @param organizationId - Optional, used to check permissions for a specific organization
 * @returns True if the user has permission for the specified resource and action, false otherwise
 * @example
 * // Usage in a component:
 * function UserManagementPage() {
 *   const canCreateUser = usePermission('user', 'create');
 *   const canEditUser = usePermission('user', 'edit');
 *   
 *   return (
 *     <div>
 *       {canCreateUser && <Button>Add New User</Button>}
 *       <UserList canEdit={canEditUser} />
 *     </div>
 *   );
 * }
 */
export function usePermission(
  resourceSlug: string,
  actionSlug: string,
  organizationId?: string
): boolean {
  // Client-side permission check using the session data
  const { data: session } = useSession();
  if (!session) return false;

  // System admin can do anything
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
 * A Higher-Order Component (HOC) that performs permission checks
 * Renders the component if permission exists for the specified resource and action, otherwise returns null
 * @param Component - The React component to wrap
 * @param resourceSlug - The resource slug to check (e.g., 'user', 'role', 'organization')
 * @param actionSlug - The action slug to check (e.g., 'create', 'view', 'edit', 'delete')
 * @param organizationId - Optional, used to check permissions for a specific organization
 * @returns A new component that wraps the original component with permission checking
 * @example
 * // Usage example:
 * const UserCreateButton = withPermission(CreateButton, 'user', 'create');
 * 
 * // With permission check for a specific organization:
 * const OrgSettingsPanel = withPermission(SettingsPanel, 'organization', 'edit', organization.id);
 * 
 * // Then you can use these components normally:
 * return (
 *   <div>
 *     <UserCreateButton onClick={handleCreate} />
 *     <OrgSettingsPanel settings={settings} />
 *   </div>
 * );
 */
export function withPermission<P extends object>(
  Component: React.ComponentType<P>,
  resourceSlug: string,
  actionSlug: string,
  organizationId?: string
): React.FC<P> {
  const PermissionWrapper: React.FC<P> = (props) => {
    const hasPermission = usePermission(resourceSlug, actionSlug, organizationId);

    if (!hasPermission) {
      return null;
    }

    return React.createElement(Component, props);
  };

  // Copy display name for better debugging
  PermissionWrapper.displayName = `WithPermission(${
    Component.displayName || Component.name || 'Component'
  })`;

  return PermissionWrapper;
}
