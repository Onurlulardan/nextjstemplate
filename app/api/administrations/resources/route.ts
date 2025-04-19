import { NextResponse, NextRequest } from 'next/server';
import knex from '@/knex';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/server-permissions';

// GET /api/resources
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('resource', 'view');

    // Get all resources
    const resources = await knex('Resource').select(
      'id',
      'name',
      'description',
      'createdAt',
      'updatedAt'
    );

    // For each resource, count related permissions
    for (const resource of resources) {
      const permissionCount = await knex('Permission')
        .where({ resourceId: resource.id })
        .count('id as count')
        .first();
      
      resource._count = {
        permissions: parseInt(permissionCount?.count?.toString() || '0', 10)
      };
    }

    return NextResponse.json(resources);
  } catch (error) {
    console.error('[RESOURCES_GET]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// POST /api/resources
export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('resource', 'create');

    const body = await request.json();
    const { name, description } = body;

    if (!name) {
      return new NextResponse('Name is required', { status: 400 });
    }

    // Create resource
    const [resource] = await knex('Resource')
      .insert({
        id: knex.raw('uuid_generate_v4()'),
        name,
        description,
        createdAt: knex.fn.now(),
        updatedAt: knex.fn.now()
      })
      .returning(['id', 'name', 'description', 'createdAt', 'updatedAt']);

    return NextResponse.json(resource, { status: 201 });
  } catch (error) {
    console.error('[RESOURCES_POST]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
