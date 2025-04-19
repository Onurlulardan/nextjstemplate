import { NextResponse, NextRequest } from 'next/server';
import knex from '@/knex';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/server-permissions';

// GET /api/organizations
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('organization', 'view');

    // Get all organizations
    const organizations = await knex('Organization')
      .select(
        'id',
        'name',
        'slug',
        'status',
        'ownerId',
        'parentId',
        'createdAt',
        'updatedAt'
      );

    // For each organization, get related data
    for (const org of organizations) {
      // Get owner information
      const owner = await knex('User')
        .where({ id: org.ownerId })
        .select('id', 'email', 'firstName', 'lastName')
        .first();
      org.owner = owner || null;

      // Get children organizations
      const children = await knex('Organization')
        .where({ parentId: org.id })
        .select('id', 'name', 'slug');
      org.children = children;

      // Count members
      const [memberCount] = await knex('OrganizationMember')
        .where({ organizationId: org.id })
        .count('* as count');
      org._count = {
        members: parseInt(memberCount.count as string, 10)
      };
    }

    return NextResponse.json(organizations);
  } catch (error) {
    console.error('[ORGANIZATIONS_GET]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// POST /api/organizations
export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('organization', 'create');

    const body = await request.json();
    const { name, slug, status, parentId } = body;

    if (!name || !slug) {
      return new NextResponse('Missing required fields', { status: 400 });
    }

    // Check if organization with slug already exists
    const existingOrg = await knex('Organization')
      .where({ slug })
      .first();

    if (existingOrg) {
      return new NextResponse('Organization with this slug already exists', { status: 400 });
    }

    // Create organization
    const [organization] = await knex('Organization')
      .insert({
        id: knex.raw('uuid_generate_v4()'),
        name,
        slug,
        status,
        ownerId: session.user.id,
        createdAt: knex.fn.now(),
        updatedAt: knex.fn.now()
      })
      .returning('*');

    return NextResponse.json(organization, { status: 201 });
  } catch (error) {
    console.error('[ORGANIZATIONS_POST]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
