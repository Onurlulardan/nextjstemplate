import { NextResponse, NextRequest } from 'next/server';
import knex from '@/knex';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/server-permissions';

// GET /api/roles
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('role', 'view');

    // Get all roles
    const roles = await knex('Role')
      .select(
        'Role.id',
        'Role.name',
        'Role.description',
        'Role.isDefault',
        'Role.organizationId',
        'Role.createdAt',
        'Role.updatedAt'
      );

    // For each role, get related data
    for (const role of roles) {
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
          roleId: role.id,
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

      // Count user roles
      const [userRoleCount] = await knex('UserRole')
        .where({ roleId: role.id })
        .count('* as count');
      
      role._count = {
        userRoles: parseInt(userRoleCount.count as string, 10)
      };
    }

    return NextResponse.json(roles);
  } catch (error) {
    console.error('[ROLES_GET]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// POST /api/roles
export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('role', 'create');

    const body = await request.json();
    const { name, description, isDefault, organizationId } = body;

    if (!name) {
      return new NextResponse('Missing required fields', { status: 400 });
    }

    // Check if role with name already exists
    const existingRole = await knex('Role')
      .where({
        name,
        organizationId: organizationId || null
      })
      .first();

    if (existingRole) {
      return new NextResponse('Role with this name already exists in the organization', {
        status: 400,
      });
    }

    if (isDefault) {
      const role = await knex.transaction(async (trx) => {
        // Reset default flag for other roles in the same organization context
        if (organizationId) {
          await trx('Role')
            .where({
              organizationId,
              isDefault: true
            })
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
            .update({
              isDefault: false,
              updatedAt: trx.fn.now()
            });
        }

        // Create new role with default flag
        const [newRole] = await trx('Role')
          .insert({
            id: trx.raw('uuid_generate_v4()'),
            name,
            description,
            isDefault: true,
            organizationId,
            createdAt: trx.fn.now(),
            updatedAt: trx.fn.now()
          })
          .returning('*');

        // Get organization if exists
        let organization = null;
        if (organizationId) {
          organization = await trx('Organization')
            .where({ id: organizationId })
            .select('id', 'name', 'slug')
            .first();
        }

        return {
          ...newRole,
          organization
        };
      });

      return NextResponse.json(role, { status: 201 });
    } else {
      // Create role without default flag (simpler case)
      const [role] = await knex('Role')
        .insert({
          id: knex.raw('uuid_generate_v4()'),
          name,
          description,
          isDefault: false,
          organizationId,
          createdAt: knex.fn.now(),
          updatedAt: knex.fn.now()
        })
        .returning('*');

      // Get organization if exists
      let organization = null;
      if (organizationId) {
        organization = await knex('Organization')
          .where({ id: organizationId })
          .select('id', 'name', 'slug')
          .first();
      }

      return NextResponse.json({ ...role, organization }, { status: 201 });
    }
  } catch (error) {
    console.error('[ROLES_POST]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
