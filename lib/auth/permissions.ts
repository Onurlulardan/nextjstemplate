import { getServerSession } from 'next-auth';
import { useSession } from 'next-auth/react';
import { authOptions } from './auth-options';
import { redirect } from 'next/navigation';
import { OrganizationMembership, Permission } from './types';
import React from 'react';

function hasActionPermission(permission: Permission, actionSlug: string): boolean {
  return permission.actions.some(
    (a) => a.slug === actionSlug || a.slug === 'manage'
  );
}

function checkResourcePermission(
  permissions: Permission[],
  resourceSlug: string,
  actionSlug: string
): boolean {
  return permissions.some(
    (p) =>
      // Check for specific resource permission
      ((p.resource.slug === resourceSlug || p.resource.slug === '*') &&
        hasActionPermission(p, actionSlug))
  );
}

export async function checkPermission(
  resourceSlug: string,
  actionSlug: string,
  organizationId?: string
): Promise<boolean> {
  const session = await getServerSession(authOptions);
  if (!session) return false;

  // System admin can do anything
  if (session.user.role === 'ADMIN') return true;

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
    const hasRolePermission = checkResourcePermission(
      rolePermissions,
      resourceSlug,
      actionSlug
    );

    if (hasRolePermission) return true;

    // Check organization-level permissions
    const organizationPermissions = membership.organization.permissions;
    return checkResourcePermission(
      organizationPermissions,
      resourceSlug,
      actionSlug
    );
  }

  // If no organizationId is provided, check permissions across all organizations
  return session.user.memberships.some((membership: OrganizationMembership) => {
    // Check role-based permissions
    const rolePermissions = membership.role?.permissions || [];
    const hasRolePermission = checkResourcePermission(
      rolePermissions,
      resourceSlug,
      actionSlug
    );

    if (hasRolePermission) return true;

    // Check organization-level permissions
    return checkResourcePermission(
      membership.organization.permissions,
      resourceSlug,
      actionSlug
    );
  });
}

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

export function usePermission(
  resourceSlug: string,
  actionSlug: string,
  organizationId?: string
): boolean {
  // Client-side permission check using the session data
  const { data: session } = useSession();
  if (!session) return false;

  // System admin can do anything
  if (session.user.role === 'ADMIN') return true;

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
    const hasRolePermission = checkResourcePermission(
      rolePermissions,
      resourceSlug,
      actionSlug
    );

    if (hasRolePermission) return true;

    // Check organization-level permissions
    const organizationPermissions = membership.organization.permissions;
    return checkResourcePermission(
      organizationPermissions,
      resourceSlug,
      actionSlug
    );
  }

  // If no organizationId is provided, check permissions across all organizations
  return session.user.memberships.some((membership: OrganizationMembership) => {
    // Check role-based permissions
    const rolePermissions = membership.role?.permissions || [];
    const hasRolePermission = checkResourcePermission(
      rolePermissions,
      resourceSlug,
      actionSlug
    );

    if (hasRolePermission) return true;

    // Check organization-level permissions
    return checkResourcePermission(
      membership.organization.permissions,
      resourceSlug,
      actionSlug
    );
  });
}

// Higher-order component for permission-based rendering
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
