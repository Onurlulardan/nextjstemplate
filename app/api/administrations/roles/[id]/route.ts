import { NextResponse, NextRequest } from 'next/server';
import knex from '@/knex';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/server-permissions';

// GET /api/roles/[id]
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('role', 'view');

    const { id } = await params;

    // Get role details
    const role = await knex('Role')
      .where({ id })
      .first(
        'id',
        'name',
        'description',
        'isDefault',
        'organizationId',
        'createdAt',
        'updatedAt'
      );

    if (role) {
      // Get organization if exists
      if (role.organizationId) {
        const organization = await knex('Organization')
          .where({ id: role.organizationId })
          .select('id', 'name', 'slug')
          .first();
        role.organization = organization || null;
      } else {
        role.organization = null;
      }

      // Get permissions
      const permissions = await knex('Permission')
        .where({ 
          roleId: id,
          target: 'ROLE'
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
      for (const permission of permissions) {
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
      role.permissions = permissionsWithActions;

      // Get user roles
      const userRoles = await knex('UserRole')
        .where({ roleId: id })
        .join('User', 'UserRole.userId', 'User.id')
        .select(
          'UserRole.id as userRoleId',
          'User.id as userId',
          'User.email',
          'User.firstName',
          'User.lastName'
        );

      role.userRoles = userRoles.map(ur => ({
        id: ur.userRoleId,
        user: {
          id: ur.userId,
          email: ur.email,
          firstName: ur.firstName,
          lastName: ur.lastName
        }
      }));
    }

    if (!role) {
      return new NextResponse('Role not found', { status: 404 });
    }

    return NextResponse.json(role);
  } catch (error) {
    console.error('[ROLE_GET]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// PUT /api/roles/[id]
export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('role', 'edit');

    const { id } = await params;
    const body = await request.json();
    const { name, description, isDefault } = body;

    if (!name && description === undefined && isDefault === undefined) {
      return new NextResponse('No fields to update', { status: 400 });
    }

    // Check if role exists
    const existingRole = await knex('Role')
      .where({ id })
      .first();

    if (!existingRole) {
      return new NextResponse('Role not found', { status: 404 });
    }

    // If name is being changed, check if new name is already in use in the same organization
    if (name && name !== existingRole.name) {
      const nameExists = await knex('Role')
        .where({
          name,
          organizationId: existingRole.organizationId
        })
        .whereNot('id', id)
        .first();

      if (nameExists) {
        return new NextResponse('Role with this name already exists in the organization', {
          status: 400,
        });
      }
    }

    if (isDefault === true) {
      const updatedRole = await knex.transaction(async (trx) => {
        // Reset default flag for other roles in the same organization context
        if (existingRole.organizationId) {
          await trx('Role')
            .where({
              organizationId: existingRole.organizationId,
              isDefault: true
            })
            .whereNot('id', id)
            .update({
              isDefault: false,
              updatedAt: trx.fn.now()
            });
        } else {
          await trx('Role')
            .where({
              organizationId: null,
              isDefault: true
            })
            .whereNot('id', id)
            .update({
              isDefault: false,
              updatedAt: trx.fn.now()
            });
        }

        // Update current role
        const updateData = {
          ...(name && { name }),
          ...(description !== undefined && { description }),
          isDefault: true,
          updatedAt: trx.fn.now()
        };

        await trx('Role')
          .where({ id })
          .update(updateData);

        // Get updated role
        const updatedRole = await trx('Role')
          .where({ id })
          .first();

        // Get organization if exists
        let organization = null;
        if (updatedRole.organizationId) {
          organization = await trx('Organization')
            .where({ id: updatedRole.organizationId })
            .select('id', 'name', 'slug')
            .first();
        }

        return {
          ...updatedRole,
          organization
        };
      });

      return NextResponse.json(updatedRole);
    } else {
      // Update role without changing default status of other roles
      const updateData = {
        ...(name && { name }),
        ...(description !== undefined && { description }),
        ...(isDefault !== undefined && { isDefault }),
        updatedAt: knex.fn.now()
      };

      await knex('Role')
        .where({ id })
        .update(updateData);

      // Get updated role
      const updatedRole = await knex('Role')
        .where({ id })
        .first();

      // Get organization if exists
      let organization = null;
      if (updatedRole.organizationId) {
        organization = await knex('Organization')
          .where({ id: updatedRole.organizationId })
          .select('id', 'name', 'slug')
          .first();
      }

      return NextResponse.json({
        ...updatedRole,
        organization
      });
    }
  } catch (error) {
    console.error('[ROLE_PUT]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// DELETE /api/roles/[id]
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('role', 'delete');

    const { id } = await params;

    // Check if role exists and count associated users
    const role = await knex('Role')
      .where({ id })
      .first();

    if (!role) {
      return new NextResponse('Role not found', { status: 404 });
    }

    // Count user roles
    const [userRoleCount] = await knex('UserRole')
      .where({ roleId: id })
      .count('* as count');
    
    const userRolesCount = parseInt(userRoleCount.count as string, 10);

    // Check if role has users
    if (userRolesCount > 0) {
      return new NextResponse(
        'Cannot delete role with assigned users. Remove users from this role first.',
        {
          status: 400,
        }
      );
    }

    // Delete role and related permissions in a transaction
    await knex.transaction(async (trx) => {
      // First delete related permissions
      await trx('Permission').where({ roleId: id, target: 'ROLE' }).delete();
      
      // Then delete the role
      await trx('Role').where({ id }).delete();
    });

    return new NextResponse(null, { status: 204 });
  } catch (error) {
    console.error('[ROLE_DELETE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
