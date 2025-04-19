import { NextResponse, NextRequest } from 'next/server';
import knex from '@/knex';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/server-permissions';

// GET /api/permissions/[id]
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('permission', 'view');

    const { id } = await params;

    // Get permission by id
    const permission = await knex('Permission')
      .where({ id })
      .first(
        'id',
        'resourceId',
        'target',
        'userId',
        'roleId',
        'organizationId',
        'createdAt',
        'updatedAt'
      );

    if (permission) {
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

    if (!permission) {
      return new NextResponse('Permission not found', { status: 404 });
    }

    return NextResponse.json(permission);
  } catch (error) {
    console.error('[PERMISSION_GET]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// PUT /api/permissions/[id]
export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('permission', 'edit');

    const { id } = await params;
    const body = await request.json();
    const { resourceId, actionIds } = body;

    // Check if permission exists
    const existingPermission = await knex('Permission').where({ id }).first();

    if (!existingPermission) {
      return new NextResponse('Permission not found', { status: 404 });
    }

    // Delete existing permission actions
    await knex('PermissionAction').where({ permissionId: id }).delete();

    // Update permission using transaction
    const permission = await knex.transaction(async (trx) => {
      // 1. Update permission record
      await trx('Permission').where({ id }).update({
        resourceId,
        updatedAt: trx.fn.now(),
      });

      // 2. Create new permission actions
      for (const actionId of actionIds) {
        await trx('PermissionAction').insert({
          id: trx.raw('uuid_generate_v4()'),
          permissionId: id,
          actionId,
          createdAt: trx.fn.now(),
          updatedAt: trx.fn.now(),
        });
      }

      // 3. Get updated permission
      const updatedPermission = await trx('Permission')
        .where({ id })
        .first(
          'id',
          'resourceId',
          'target',
          'userId',
          'roleId',
          'organizationId',
          'createdAt',
          'updatedAt'
        );

      // 4. Get resource
      const resource = await trx('Resource').where({ id: updatedPermission.resourceId }).first();
      updatedPermission.resource = resource;

      // 5. Get actions
      const permissionActions = await trx('PermissionAction')
        .where({ permissionId: updatedPermission.id })
        .join('Action', 'PermissionAction.actionId', 'Action.id')
        .select(
          'PermissionAction.id',
          'Action.id as actionId',
          'Action.name as actionName',
          'Action.description as actionDescription'
        );

      updatedPermission.actions = permissionActions.map((pa) => ({
        id: pa.id,
        action: {
          id: pa.actionId,
          name: pa.actionName,
          description: pa.actionDescription,
        },
      }));

      // 6. Get target-specific data based on target type
      if (updatedPermission.target === 'USER' && updatedPermission.userId) {
        const user = await trx('User')
          .where({ id: updatedPermission.userId })
          .select('id', 'email', 'firstName', 'lastName')
          .first();
        updatedPermission.user = user || null;
      } else {
        updatedPermission.user = null;
      }

      if (updatedPermission.target === 'ROLE' && updatedPermission.roleId) {
        const role = await trx('Role')
          .where({ id: updatedPermission.roleId })
          .select('id', 'name', 'organizationId')
          .first();
        updatedPermission.role = role || null;
      } else {
        updatedPermission.role = null;
      }

      if (updatedPermission.target === 'ORGANIZATION' && updatedPermission.organizationId) {
        const organization = await trx('Organization')
          .where({ id: updatedPermission.organizationId })
          .select('id', 'name')
          .first();
        updatedPermission.organization = organization || null;
      } else {
        updatedPermission.organization = null;
      }

      return updatedPermission;
    });

    return NextResponse.json(permission);
  } catch (error) {
    console.error('[PERMISSION_PUT]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// DELETE /api/permissions/[id]
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('permission', 'delete');

    const { id } = await params;

    // Check if permission exists
    const permission = await knex('Permission').where({ id }).first();

    if (!permission) {
      return new NextResponse('Permission not found', { status: 404 });
    }

    // Delete permission and related actions using transaction
    await knex.transaction(async (trx) => {
      // First delete related permission actions
      await trx('PermissionAction').where({ permissionId: id }).delete();

      // Then delete the permission
      await trx('Permission').where({ id }).delete();
    });

    return new NextResponse(null, { status: 204 });
  } catch (error) {
    console.error('[PERMISSION_DELETE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
