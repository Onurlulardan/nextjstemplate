import { NextResponse, NextRequest } from 'next/server';
import knex from '@/knex';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/server-permissions';

// POST /api/organizations/[id]/add-users
export async function POST(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('organization', 'update');

    const { userIds } = await request.json();
    const { id } = await params;
    const organizationId = id;

    // Validate input
    if (!userIds || !Array.isArray(userIds)) {
      return new NextResponse('Invalid user IDs', { status: 400 });
    }

    // Get existing members
    const existingMembers = await knex('OrganizationMember')
      .where({ organizationId })
      .whereIn('userId', userIds);

    const existingUserIds = existingMembers.map((member) => member.userId);
    const newUserIds = userIds.filter((id) => !existingUserIds.includes(id));

    // Add new members
    let addedCount = 0;
    if (newUserIds.length > 0) {
      // Use transaction to ensure all inserts succeed or fail together
      await knex.transaction(async (trx) => {
        // Insert each new member
        for (const userId of newUserIds) {
          await trx('OrganizationMember').insert({
            id: trx.raw('uuid_generate_v4()'),
            organizationId,
            userId,
            createdAt: trx.fn.now(),
            updatedAt: trx.fn.now()
          });
          addedCount++;
        }
      });
    }

    return NextResponse.json({
      added: addedCount,
      skipped: existingUserIds.length,
    });
  } catch (error) {
    console.error('[ORGANIZATIONS_ADD_USERS_POST]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
