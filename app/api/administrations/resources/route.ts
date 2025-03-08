import { NextResponse, NextRequest } from 'next/server';
import { prisma } from '@/lib/prisma';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/permissions';

// GET /api/resources
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('resource', 'view');

    const resources = await prisma.resource.findMany({
      include: {
        _count: {
          select: {
            permissions: true,
          },
        },
      },
    });

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
    const { name, slug, description } = body;

    if (!name || !slug) {
      return new NextResponse('Missing required fields', { status: 400 });
    }

    // Check if resource with same slug already exists
    const existingResource = await prisma.resource.findUnique({
      where: { slug },
    });

    if (existingResource) {
      return new NextResponse('Resource with this slug already exists', { status: 400 });
    }

    const resource = await prisma.resource.create({
      data: {
        name,
        slug,
        description,
      },
    });

    return NextResponse.json(resource, { status: 201 });
  } catch (error) {
    console.error('[RESOURCES_POST]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
