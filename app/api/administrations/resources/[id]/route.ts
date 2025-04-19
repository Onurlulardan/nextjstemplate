import { NextResponse, NextRequest } from 'next/server';
import knex from '@/knex';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/server-permissions';

// GET /api/resources/[id]
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('resource', 'view');

    const { id } = await params;

    // Get resource by id
    const resource = await knex('Resource')
      .where({ id })
      .first(
        'id',
        'name',
        'description',
        'createdAt',
        'updatedAt'
      );

    if (resource) {
      // Count related permissions
      const permissionCount = await knex('Permission')
        .where({ resourceId: id })
        .count('id as count')
        .first();

      resource._count = {
        permissions: parseInt(permissionCount?.count?.toString() || '0', 10)
      };
    }

    if (!resource) {
      return new NextResponse('Resource not found', { status: 404 });
    }

    return NextResponse.json(resource);
  } catch (error) {
    console.error('[RESOURCE_GET]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// PUT /api/resources/[id]
export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('resource', 'edit');

    const { id } = await params;
    const body = await request.json();
    const { name, description } = body;

    if (!name) {
      return new NextResponse('Name is required', { status: 400 });
    }

    // Check if resource exists
    const existingResource = await knex('Resource')
      .where({ id })
      .first();

    if (!existingResource) {
      return new NextResponse('Resource not found', { status: 404 });
    }

    // Update resource
    const [resource] = await knex('Resource')
      .where({ id })
      .update({
        name,
        description,
        updatedAt: knex.fn.now()
      })
      .returning(['id', 'name', 'description', 'createdAt', 'updatedAt']);

    return NextResponse.json(resource);
  } catch (error) {
    console.error('[RESOURCE_PUT]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// DELETE /api/resources/[id]
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('resource', 'delete');

    const { id } = await params;

    // Check if resource exists and has no associated permissions
    const existingResource = await knex('Resource')
      .where({ id })
      .first();

    if (!existingResource) {
      return new NextResponse('Resource not found', { status: 404 });
    }

    // Count related permissions
    const permissionCount = await knex('Permission')
      .where({ resourceId: id })
      .count('id as count')
      .first();

    const permissionsCount = parseInt(permissionCount?.count?.toString() || '0', 10);

    if (permissionsCount > 0) {
      return new NextResponse('Cannot delete resource that has associated permissions', {
        status: 400,
      });
    }

    // Delete resource
    await knex('Resource')
      .where({ id })
      .delete();

    return new NextResponse(null, { status: 204 });
  } catch (error) {
    console.error('[RESOURCE_DELETE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
