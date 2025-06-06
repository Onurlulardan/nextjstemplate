import { NextResponse, NextRequest } from 'next/server';
import knex from '@/knex';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/server-permissions';

// GET /api/organizations/available-parents?organizationId=xxx
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('organization', 'view');

    // Get organizationId from query params
    const { searchParams } = new URL(request.url);
    const organizationId = searchParams.get('organizationId');

    // Get all organizations first
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

    // For each organization, get its children
    for (const org of organizations) {
      const children = await knex('Organization')
        .where({ parentId: org.id })
        .select('id', 'name', 'slug');
      org.children = children;
    }

    if (organizationId) {
      // Recursive function to get all child IDs
      const getChildIds = (orgId: string): string[] => {
        const children = organizations.filter((org) => org.parentId === orgId);
        return [orgId, ...children.flatMap((child) => getChildIds(child.id))];
      };

      // Filter out the organization itself and all its children
      const excludeIds = getChildIds(organizationId);
      const availableParents = organizations.filter((org) => !excludeIds.includes(org.id));

      return NextResponse.json(availableParents);
    }

    return NextResponse.json(organizations);
  } catch (error) {
    console.error('[ORGANIZATIONS_AVAILABLE_PARENTS_GET]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
