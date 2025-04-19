import { NextResponse, NextRequest } from 'next/server';
import knex from '@/knex';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/server-permissions';

// GET /api/permissions
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('permission', 'view');

    // Get all permissions
    const permissions = await knex('Permission').select(
      'Permission.id',
      'Permission.resourceId',
      'Permission.target',
      'Permission.userId',
      'Permission.roleId',
      'Permission.organizationId',
      'Permission.createdAt',
      'Permission.updatedAt'
    );

    // For each permission, get related data
    for (const permission of permissions) {
      // Get resource
      const resource = await knex('Resource').where({ id: permission.resourceId }).first();
      permission.resource = resource;

      // Get actions
      const permissionActions = await knex('PermissionAction')
        .where({ permissionId: permission.id })
        .join('Action', 'PermissionAction.actionId', 'Action.id')
        .select(
          'PermissionAction.id',
          'Action.id as actionId',
          'Action.name as actionName',
          'Action.description as actionDescription'
        );

      permission.actions = permissionActions.map((pa) => ({
        id: pa.id,
        action: {
          id: pa.actionId,
          name: pa.actionName,
          description: pa.actionDescription,
        },
      }));

      // Get target-specific data based on target type
      if (permission.target === 'USER' && permission.userId) {
        const user = await knex('User')
          .where({ id: permission.userId })
          .select('id', 'email', 'firstName', 'lastName')
          .first();
        permission.user = user || null;
      } else {
        permission.user = null;
      }

      if (permission.target === 'ROLE' && permission.roleId) {
        const role = await knex('Role')
          .where({ id: permission.roleId })
          .select('id', 'name', 'organizationId')
          .first();
        permission.role = role || null;
      } else {
        permission.role = null;
      }

      if (permission.target === 'ORGANIZATION' && permission.organizationId) {
        const organization = await knex('Organization')
          .where({ id: permission.organizationId })
          .select('id', 'name')
          .first();
        permission.organization = organization || null;
      } else {
        permission.organization = null;
      }
    }

    return NextResponse.json(permissions);
  } catch (error) {
    console.error('[PERMISSIONS_GET]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// POST /api/permissions
export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('permission', 'create');

    const body = await request.json();
    const { resourceId, target, userId, roleId, organizationId, actionIds } = body;

    if (!resourceId || !target || !actionIds?.length) {
      return new NextResponse('Missing required fields', { status: 400 });
    }

    // Validate target type
    if (!['USER', 'ROLE', 'ORGANIZATION'].includes(target)) {
      return new NextResponse('Invalid target type', { status: 400 });
    }

    // Check that only one target ID is provided
    const targetIds = [userId, roleId, organizationId].filter(Boolean);
    if (targetIds.length !== 1) {
      return new NextResponse('Exactly one target ID must be provided', { status: 400 });
    }

    // Create permission using transaction
    const permission = await knex.transaction(async (trx) => {
      // 1. Create permission record
      const [newPermission] = await trx('Permission')
        .insert({
          id: trx.raw('uuid_generate_v4()'),
          resourceId,
          target,
          userId: target === 'USER' ? userId : null,
          roleId: target === 'ROLE' ? roleId : null,
          organizationId: target === 'ORGANIZATION' ? organizationId : null,
          createdAt: trx.fn.now(),
          updatedAt: trx.fn.now(),
        })
        .returning('*');

      // 2. Create permission actions
      for (const actionId of actionIds) {
        await trx('PermissionAction').insert({
          id: trx.raw('uuid_generate_v4()'),
          permissionId: newPermission.id,
          actionId,
          createdAt: trx.fn.now(),
          updatedAt: trx.fn.now(),
        });
      }

      // 3. Get resource
      const resource = await trx('Resource').where({ id: resourceId }).first();
      newPermission.resource = resource;

      // 4. Get actions
      const permissionActions = await trx('PermissionAction')
        .where({ permissionId: newPermission.id })
        .join('Action', 'PermissionAction.actionId', 'Action.id')
        .select(
          'PermissionAction.id',
          'Action.id as actionId',
          'Action.name as actionName',
          'Action.description as actionDescription'
        );

      newPermission.actions = permissionActions.map((pa) => ({
        id: pa.id,
        action: {
          id: pa.actionId,
          name: pa.actionName,
          description: pa.actionDescription,
        },
      }));

      // 5. Get target-specific data based on target type
      if (target === 'USER' && userId) {
        const user = await trx('User')
          .where({ id: userId })
          .select('id', 'email', 'firstName', 'lastName')
          .first();
        newPermission.user = user || null;
      } else {
        newPermission.user = null;
      }

      if (target === 'ROLE' && roleId) {
        const role = await trx('Role')
          .where({ id: roleId })
          .select('id', 'name', 'organizationId')
          .first();
        newPermission.role = role || null;
      } else {
        newPermission.role = null;
      }

      if (target === 'ORGANIZATION' && organizationId) {
        const organization = await trx('Organization')
          .where({ id: organizationId })
          .select('id', 'name')
          .first();
        newPermission.organization = organization || null;
      } else {
        newPermission.organization = null;
      }

      return newPermission;
    });

    return NextResponse.json(permission, { status: 201 });
  } catch (error) {
    console.error('[PERMISSIONS_POST]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
