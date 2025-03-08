import { NextResponse, NextRequest } from 'next/server';
import { prisma } from '@/lib/prisma';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/permissions';

// GET /api/resources/[id]
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('resource', 'view');

    const { id } = await params;

    const resource = await prisma.resource.findUnique({
      where: { id },
      include: {
        _count: {
          select: {
            permissions: true,
          },
        },
      },
    });

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
    const { name, slug, description } = body;

    if (!name || !slug) {
      return new NextResponse('Missing required fields', { status: 400 });
    }

    // Check if resource exists
    const existingResource = await prisma.resource.findUnique({
      where: { id },
    });

    if (!existingResource) {
      return new NextResponse('Resource not found', { status: 404 });
    }

    // If slug is being changed, check if new slug is already in use
    if (slug !== existingResource.slug) {
      const slugExists = await prisma.resource.findUnique({
        where: { slug },
      });

      if (slugExists) {
        return new NextResponse('Resource with this slug already exists', { status: 400 });
      }
    }

    const resource = await prisma.resource.update({
      where: { id },
      data: {
        name,
        slug,
        description,
      },
    });

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
    const existingResource = await prisma.resource.findUnique({
      where: { id },
      include: {
        _count: {
          select: {
            permissions: true,
          },
        },
      },
    });

    if (!existingResource) {
      return new NextResponse('Resource not found', { status: 404 });
    }

    if (existingResource._count.permissions > 0) {
      return new NextResponse('Cannot delete resource that has associated permissions', {
        status: 400,
      });
    }

    await prisma.resource.delete({
      where: { id },
    });

    return new NextResponse(null, { status: 204 });
  } catch (error) {
    console.error('[RESOURCE_DELETE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
