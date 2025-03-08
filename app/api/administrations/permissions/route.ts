import { NextResponse, NextRequest } from 'next/server';
import { prisma } from '@/lib/prisma';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/permissions';

// GET /api/permissions
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('permission', 'view');

    const permissions = await prisma.permission.findMany({
      include: {
        resource: true,
        actions: {
          include: {
            action: true,
          },
        },
        user: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
          },
        },
        role: {
          select: {
            id: true,
            name: true,
            organizationId: true,
          },
        },
        organization: {
          select: {
            id: true,
            name: true,
          },
        },
      },
    });

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

    // Create permission
    const permission = await prisma.permission.create({
      data: {
        resourceId,
        target,
        userId,
        roleId,
        organizationId,
        actions: {
          create: actionIds.map((actionId: string) => ({
            action: {
              connect: { id: actionId },
            },
          })),
        },
      },
      include: {
        resource: true,
        actions: {
          include: {
            action: true,
          },
        },
        user: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
          },
        },
        role: {
          select: {
            id: true,
            name: true,
            organizationId: true,
          },
        },
        organization: {
          select: {
            id: true,
            name: true,
          },
        },
      },
    });

    return NextResponse.json(permission, { status: 201 });
  } catch (error) {
    console.error('[PERMISSIONS_POST]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
