import { NextResponse, NextRequest } from 'next/server';
import knex from '@/knex';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/server-permissions';

// GET /api/actions/[id]
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('action', 'view');

    const { id } = await params;

    // Get action by id
    const action = await knex('Action')
      .where({ id })
      .first('id', 'name', 'description', 'createdAt', 'updatedAt');

    if (action) {
      // Count related permission actions
      const permissionCount = await knex('PermissionAction')
        .where({ actionId: id })
        .count('id as count')
        .first();

      action._count = {
        permissions: parseInt(permissionCount?.count?.toString() || '0', 10),
      };
    }

    if (!action) {
      return new NextResponse('Action not found', { status: 404 });
    }

    return NextResponse.json(action);
  } catch (error) {
    console.error('[ACTION_GET]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// PUT /api/actions/[id]
export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('action', 'edit');

    const { id } = await params;
    const body = await request.json();
    const { name, description } = body;

    if (!name) {
      return new NextResponse('Name is required', { status: 400 });
    }

    // Check if action exists
    const existingAction = await knex('Action').where({ id }).first();

    if (!existingAction) {
      return new NextResponse('Action not found', { status: 404 });
    }

    // Check if name is being changed and if new name is already taken
    if (name !== existingAction.name) {
      const nameExists = await knex('Action').where({ name }).whereNot({ id }).first();

      if (nameExists) {
        return new NextResponse('Action with this name already exists', { status: 400 });
      }
    }

    // Update action
    const [action] = await knex('Action')
      .where({ id })
      .update({
        name,
        description,
        updatedAt: knex.fn.now(),
      })
      .returning(['id', 'name', 'description', 'createdAt', 'updatedAt']);

    return NextResponse.json(action);
  } catch (error) {
    console.error('[ACTION_PUT]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// DELETE /api/actions/[id]
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('action', 'delete');

    const { id } = await params;

    // Check if action exists
    const existingAction = await knex('Action').where({ id }).first();

    if (!existingAction) {
      return new NextResponse('Action not found', { status: 404 });
    }

    // Check if action has associated permission actions
    const permissionCount = await knex('PermissionAction')
      .where({ actionId: id })
      .count('id as count')
      .first();

    const permissionsCount = parseInt(permissionCount?.count?.toString() || '0', 10);

    if (permissionsCount > 0) {
      return new NextResponse('Cannot delete action that has associated permissions', {
        status: 400,
      });
    }

    // Delete action
    await knex('Action').where({ id }).delete();

    return NextResponse.json({ message: 'Action deleted successfully' });
  } catch (error) {
    console.error('[ACTION_DELETE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
