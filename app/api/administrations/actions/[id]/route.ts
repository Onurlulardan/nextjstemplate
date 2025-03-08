import { NextResponse, NextRequest } from 'next/server';
import { prisma } from '@/lib/prisma';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/permissions';

// GET /api/actions/[id]
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('action', 'view');

    const { id } = await params;

    const action = await prisma.action.findUnique({
      where: { id },
      include: {
        _count: {
          select: {
            permissions: true,
          },
        },
      },
    });

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
    const { name, slug, description } = body;

    if (!name || !slug) {
      return new NextResponse('Missing required fields', { status: 400 });
    }

    // Check if action exists
    const existingAction = await prisma.action.findUnique({
      where: { id },
    });

    if (!existingAction) {
      return new NextResponse('Action not found', { status: 404 });
    }

    // If slug is being changed, check if new slug is already in use
    if (slug !== existingAction.slug) {
      const slugExists = await prisma.action.findUnique({
        where: { slug },
      });

      if (slugExists) {
        return new NextResponse('Action with this slug already exists', { status: 400 });
      }
    }

    const action = await prisma.action.update({
      where: { id },
      data: {
        name,
        slug,
        description,
      },
    });

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

    // Check if action exists and has no associated permissions
    const existingAction = await prisma.action.findUnique({
      where: { id },
      include: {
        _count: {
          select: {
            permissions: true,
          },
        },
      },
    });

    if (!existingAction) {
      return new NextResponse('Action not found', { status: 404 });
    }

    if (existingAction._count.permissions > 0) {
      return new NextResponse('Cannot delete action with associated permissions', { status: 400 });
    }

    // Delete action
    await prisma.action.delete({
      where: { id },
    });

    return NextResponse.json({ message: 'Action deleted successfully' });
  } catch (error) {
    console.error('[ACTION_DELETE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
