import { NextResponse, NextRequest } from 'next/server';
import { prisma } from '@/lib/prisma';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/permissions';

// Schema for creating/updating an action
const actionSchema = {
  name: 'string',
  slug: 'string',
  description: 'string',
};

// GET /api/actions
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('action', 'view');

    const actions = await prisma.action.findMany({
      include: {
        _count: {
          select: {
            permissions: true,
          },
        },
      },
    });

    return NextResponse.json(actions);
  } catch (error) {
    console.error('[ACTIONS_GET]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// POST /api/actions
export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('action', 'create');

    const body = await request.json();
    const { name, slug, description } = body;

    if (!name || !slug) {
      return new NextResponse('Missing required fields', { status: 400 });
    }

    // Check if action with same slug already exists
    const existingAction = await prisma.action.findUnique({
      where: { slug },
    });

    if (existingAction) {
      return new NextResponse('Action with this slug already exists', { status: 400 });
    }

    const action = await prisma.action.create({
      data: {
        name,
        slug,
        description,
      },
    });

    return NextResponse.json(action, { status: 201 });
  } catch (error) {
    console.error('[ACTIONS_POST]', error);
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

    // Check if slug is being changed and if new slug is already taken
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
    console.error('[ACTIONS_PUT]', error);
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
      return new NextResponse('Cannot delete action that has associated permissions', {
        status: 400,
      });
    }

    await prisma.action.delete({
      where: { id },
    });

    return new NextResponse(null, { status: 204 });
  } catch (error) {
    console.error('[ACTIONS_DELETE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
