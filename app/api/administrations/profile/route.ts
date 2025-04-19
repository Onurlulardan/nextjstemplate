import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import knex from '@/knex';
import { authOptions } from '@/lib/auth/auth-options';
import bcrypt from 'bcryptjs';
import { requirePermission } from '@/lib/auth/server-permissions';

export async function GET(request: Request) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('profile', 'view');

    // Get basic user info
    const user = await knex('User')
      .where({ id: session.user.id })
      .first(
        'id',
        'email',
        'firstName',
        'lastName'
      );

    if (user) {
      // Get user roles
      const userRoles = await knex('UserRole')
        .where({ userId: user.id })
        .join('Role', 'UserRole.roleId', 'Role.id')
        .select(
          'Role.id',
          'Role.name',
          'Role.description'
        );

      user.userRoles = userRoles.map(role => ({
        role: {
          id: role.id,
          name: role.name,
          description: role.description
        }
      }));

      // Get user permissions (target: USER)
      const userPermissions = await knex('Permission')
        .where({ 
          userId: user.id,
          target: 'USER'
        })
        .join('Resource', 'Permission.resourceId', 'Resource.id')
        .select(
          'Permission.id as permissionId',
          'Resource.id as resourceId',
          'Resource.name as resourceName',
          'Resource.description as resourceDescription'
        );

      // Get actions for each permission
      const permissionsWithActions = [];
      for (const permission of userPermissions) {
        const actions = await knex('PermissionAction')
          .where({ permissionId: permission.permissionId })
          .join('Action', 'PermissionAction.actionId', 'Action.id')
          .select(
            'Action.id as actionId',
            'Action.name as actionName',
            'Action.description as actionDescription'
          );

        permissionsWithActions.push({
          id: permission.permissionId,
          resource: {
            id: permission.resourceId,
            name: permission.resourceName,
            description: permission.resourceDescription
          },
          actions: actions.map(action => ({
            action: {
              id: action.actionId,
              name: action.actionName,
              description: action.actionDescription
            }
          }))
        });
      }
      user.permissions = permissionsWithActions;

      // Get user memberships
      const memberships = await knex('OrganizationMember')
        .where({ userId: user.id })
        .join('Organization', 'OrganizationMember.organizationId', 'Organization.id')
        .leftJoin('Role', 'OrganizationMember.roleId', 'Role.id')
        .select(
          'OrganizationMember.id as membershipId',
          'Organization.id as organizationId',
          'Organization.name as organizationName',
          'Organization.slug as organizationSlug',
          'Role.id as roleId',
          'Role.name as roleName',
          'Role.description as roleDescription'
        );

      // For each membership, get role permissions if role exists
      user.memberships = [];
      for (const membership of memberships) {
        const membershipObj = {
          id: membership.membershipId,
          organization: {
            id: membership.organizationId,
            name: membership.organizationName,
            slug: membership.organizationSlug
          },
          role: null as any
        };

        if (membership.roleId) {
          // Get role permissions
          const rolePermissions = await knex('Permission')
            .where({ 
              roleId: membership.roleId,
              target: 'ROLE'
            })
            .join('Resource', 'Permission.resourceId', 'Resource.id')
            .select(
              'Permission.id as permissionId',
              'Resource.id as resourceId',
              'Resource.name as resourceName',
              'Resource.description as resourceDescription'
            );

          // Get actions for each role permission
          const rolePermissionsWithActions = [];
          for (const permission of rolePermissions) {
            const actions = await knex('PermissionAction')
              .where({ permissionId: permission.permissionId })
              .join('Action', 'PermissionAction.actionId', 'Action.id')
              .select(
                'Action.id as actionId',
                'Action.name as actionName',
                'Action.description as actionDescription'
              );

            rolePermissionsWithActions.push({
              id: permission.permissionId,
              resource: {
                id: permission.resourceId,
                name: permission.resourceName,
                description: permission.resourceDescription
              },
              actions: actions.map(action => ({
                action: {
                  id: action.actionId,
                  name: action.actionName,
                  description: action.actionDescription
                }
              }))
            });
          }

          membershipObj.role = {
            id: membership.roleId,
            name: membership.roleName,
            description: membership.roleDescription,
            permissions: rolePermissionsWithActions
          };
        }

        user.memberships.push(membershipObj);
      }
    }

    if (!user) {
      return new NextResponse('User not found', { status: 404 });
    }

    return NextResponse.json(user);
  } catch (error) {
    console.error('[PROFILE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

export async function PUT(request: Request) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('profile', 'edit');

    const { email, firstName, lastName, currentPassword, newPassword } = await request.json();

    // Get current user with password for verification
    const user = await knex('User')
      .where({ id: session.user.id })
      .first(
        'id',
        'email',
        'firstName',
        'lastName',
        'password'
      );

    if (user) {
      // Get user roles
      const userRoles = await knex('UserRole')
        .where({ userId: user.id })
        .join('Role', 'UserRole.roleId', 'Role.id')
        .select(
          'Role.id',
          'Role.name',
          'Role.description'
        );

      user.userRoles = userRoles.map(role => ({
        role: {
          id: role.id,
          name: role.name,
          description: role.description
        }
      }));

      // Get user permissions (target: USER)
      const userPermissions = await knex('Permission')
        .where({ 
          userId: user.id,
          target: 'USER'
        })
        .join('Resource', 'Permission.resourceId', 'Resource.id')
        .select(
          'Permission.id as permissionId',
          'Resource.id as resourceId',
          'Resource.name as resourceName',
          'Resource.description as resourceDescription'
        );

      // Get actions for each permission
      const permissionsWithActions = [];
      for (const permission of userPermissions) {
        const actions = await knex('PermissionAction')
          .where({ permissionId: permission.permissionId })
          .join('Action', 'PermissionAction.actionId', 'Action.id')
          .select(
            'Action.id as actionId',
            'Action.name as actionName',
            'Action.description as actionDescription'
          );

        permissionsWithActions.push({
          id: permission.permissionId,
          resource: {
            id: permission.resourceId,
            name: permission.resourceName,
            description: permission.resourceDescription
          },
          actions: actions.map(action => ({
            action: {
              id: action.actionId,
              name: action.actionName,
              description: action.actionDescription
            }
          }))
        });
      }
      user.permissions = permissionsWithActions;

      // Get user memberships
      const memberships = await knex('OrganizationMember')
        .where({ userId: user.id })
        .join('Organization', 'OrganizationMember.organizationId', 'Organization.id')
        .leftJoin('Role', 'OrganizationMember.roleId', 'Role.id')
        .select(
          'OrganizationMember.id as membershipId',
          'Organization.id as organizationId',
          'Organization.name as organizationName',
          'Organization.slug as organizationSlug',
          'Role.id as roleId',
          'Role.name as roleName',
          'Role.description as roleDescription'
        );

      // For each membership, get role permissions if role exists
      user.memberships = [];
      for (const membership of memberships) {
        const membershipObj = {
          id: membership.membershipId,
          organization: {
            id: membership.organizationId,
            name: membership.organizationName,
            slug: membership.organizationSlug
          },
          role: null as any
        };

        if (membership.roleId) {
          // Get role permissions
          const rolePermissions = await knex('Permission')
            .where({ 
              roleId: membership.roleId,
              target: 'ROLE'
            })
            .join('Resource', 'Permission.resourceId', 'Resource.id')
            .select(
              'Permission.id as permissionId',
              'Resource.id as resourceId',
              'Resource.name as resourceName',
              'Resource.description as resourceDescription'
            );

          // Get actions for each role permission
          const rolePermissionsWithActions = [];
          for (const permission of rolePermissions) {
            const actions = await knex('PermissionAction')
              .where({ permissionId: permission.permissionId })
              .join('Action', 'PermissionAction.actionId', 'Action.id')
              .select(
                'Action.id as actionId',
                'Action.name as actionName',
                'Action.description as actionDescription'
              );

            rolePermissionsWithActions.push({
              id: permission.permissionId,
              resource: {
                id: permission.resourceId,
                name: permission.resourceName,
                description: permission.resourceDescription
              },
              actions: actions.map(action => ({
                action: {
                  id: action.actionId,
                  name: action.actionName,
                  description: action.actionDescription
                }
              }))
            });
          }

          membershipObj.role = {
            id: membership.roleId,
            name: membership.roleName,
            description: membership.roleDescription,
            permissions: rolePermissionsWithActions
          };
        }

        user.memberships.push(membershipObj);
      }
    }

    if (!user) {
      return new NextResponse('User not found', { status: 404 });
    }

    // Check if email is taken
    if (email && email !== user.email) {
      const existingUser = await knex('User')
        .where({ email })
        .first();

      if (existingUser) {
        return new NextResponse('Email already taken', { status: 400 });
      }
    }

    // Verify current password if changing password
    if (newPassword) {
      if (!currentPassword) {
        return new NextResponse('Current password is required', { status: 400 });
      }

      const isPasswordValid = await bcrypt.compare(currentPassword, user.password!);
      if (!isPasswordValid) {
        return new NextResponse('Current password is incorrect', { status: 400 });
      }
    }

    // Update user
    const updateData = {
      ...(email && { email }),
      ...(firstName && { firstName }),
      ...(lastName && { lastName }),
      ...(newPassword && { password: await bcrypt.hash(newPassword, 10) }),
      updatedAt: knex.fn.now()
    };

    await knex('User')
      .where({ id: session.user.id })
      .update(updateData);

    // Get updated user
    const updatedUser = await knex('User')
      .where({ id: session.user.id })
      .first(
        'id',
        'email',
        'firstName',
        'lastName'
      );

    if (updatedUser) {
      // Get user roles
      const userRoles = await knex('UserRole')
        .where({ userId: updatedUser.id })
        .join('Role', 'UserRole.roleId', 'Role.id')
        .select(
          'Role.id',
          'Role.name',
          'Role.description'
        );

      updatedUser.userRoles = userRoles.map(role => ({
        role: {
          id: role.id,
          name: role.name,
          description: role.description
        }
      }));

      // Get user permissions (target: USER)
      const userPermissions = await knex('Permission')
        .where({ 
          userId: updatedUser.id,
          target: 'USER'
        })
        .join('Resource', 'Permission.resourceId', 'Resource.id')
        .select(
          'Permission.id as permissionId',
          'Resource.id as resourceId',
          'Resource.name as resourceName',
          'Resource.description as resourceDescription'
        );

      // Get actions for each permission
      const permissionsWithActions = [];
      for (const permission of userPermissions) {
        const actions = await knex('PermissionAction')
          .where({ permissionId: permission.permissionId })
          .join('Action', 'PermissionAction.actionId', 'Action.id')
          .select(
            'Action.id as actionId',
            'Action.name as actionName',
            'Action.description as actionDescription'
          );

        permissionsWithActions.push({
          id: permission.permissionId,
          resource: {
            id: permission.resourceId,
            name: permission.resourceName,
            description: permission.resourceDescription
          },
          actions: actions.map(action => ({
            action: {
              id: action.actionId,
              name: action.actionName,
              description: action.actionDescription
            }
          }))
        });
      }
      updatedUser.permissions = permissionsWithActions;

      // Get user memberships
      const memberships = await knex('OrganizationMember')
        .where({ userId: updatedUser.id })
        .join('Organization', 'OrganizationMember.organizationId', 'Organization.id')
        .leftJoin('Role', 'OrganizationMember.roleId', 'Role.id')
        .select(
          'OrganizationMember.id as membershipId',
          'Organization.id as organizationId',
          'Organization.name as organizationName',
          'Organization.slug as organizationSlug',
          'Role.id as roleId',
          'Role.name as roleName',
          'Role.description as roleDescription'
        );

      // For each membership, get role permissions if role exists
      updatedUser.memberships = [];
      for (const membership of memberships) {
        const membershipObj = {
          id: membership.membershipId,
          organization: {
            id: membership.organizationId,
            name: membership.organizationName,
            slug: membership.organizationSlug
          },
          role: null as any
        };

        if (membership.roleId) {
          // Get role permissions
          const rolePermissions = await knex('Permission')
            .where({ 
              roleId: membership.roleId,
              target: 'ROLE'
            })
            .join('Resource', 'Permission.resourceId', 'Resource.id')
            .select(
              'Permission.id as permissionId',
              'Resource.id as resourceId',
              'Resource.name as resourceName',
              'Resource.description as resourceDescription'
            );

          // Get actions for each role permission
          const rolePermissionsWithActions = [];
          for (const permission of rolePermissions) {
            const actions = await knex('PermissionAction')
              .where({ permissionId: permission.permissionId })
              .join('Action', 'PermissionAction.actionId', 'Action.id')
              .select(
                'Action.id as actionId',
                'Action.name as actionName',
                'Action.description as actionDescription'
              );

            rolePermissionsWithActions.push({
              id: permission.permissionId,
              resource: {
                id: permission.resourceId,
                name: permission.resourceName,
                description: permission.resourceDescription
              },
              actions: actions.map(action => ({
                action: {
                  id: action.actionId,
                  name: action.actionName,
                  description: action.actionDescription
                }
              }))
            });
          }

          membershipObj.role = {
            id: membership.roleId,
            name: membership.roleName,
            description: membership.roleDescription,
            permissions: rolePermissionsWithActions
          };
        }

        updatedUser.memberships.push(membershipObj);
      }
    }

    return NextResponse.json(updatedUser);
  } catch (error) {
    console.error('[PROFILE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
