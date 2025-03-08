import { NextResponse, NextRequest } from 'next/server';
import { prisma } from '@/lib/prisma';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/permissions';

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
    const existingMembers = await prisma.organizationMember.findMany({
      where: {
        organizationId,
        userId: {
          in: userIds,
        },
      },
    });

    const existingUserIds = existingMembers.map((member) => member.userId);
    const newUserIds = userIds.filter((id) => !existingUserIds.includes(id));

    // Add new members
    const newMembers = await prisma.organizationMember.createMany({
      data: newUserIds.map((userId) => ({
        organizationId,
        userId,
      })),
    });

    return NextResponse.json({
      added: newMembers.count,
      skipped: existingUserIds.length,
    });
  } catch (error) {
    console.error('[ORGANIZATIONS_ADD_USERS_POST]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
