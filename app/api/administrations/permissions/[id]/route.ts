import { NextResponse, NextRequest } from 'next/server';
import { prisma } from '@/lib/prisma';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/permissions';

// GET /api/permissions/[id]
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('permission', 'view');

    const { id } = await params;

    const permission = await prisma.permission.findUnique({
      where: { id },
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
    const existingPermission = await prisma.permission.findUnique({
      where: { id },
    });

    if (!existingPermission) {
      return new NextResponse('Permission not found', { status: 404 });
    }

    // Delete existing permission actions
    await prisma.permissionAction.deleteMany({
      where: { permissionId: id },
    });

    // Update permission
    const permission = await prisma.permission.update({
      where: { id },
      data: {
        resourceId,
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
    const permission = await prisma.permission.findUnique({
      where: { id },
    });

    if (!permission) {
      return new NextResponse('Permission not found', { status: 404 });
    }

    // Delete permission (this will cascade delete related permission actions)
    await prisma.permission.delete({
      where: { id },
    });

    return new NextResponse(null, { status: 204 });
  } catch (error) {
    console.error('[PERMISSION_DELETE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
