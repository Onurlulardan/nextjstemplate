import { NextResponse, NextRequest } from 'next/server';
import { prisma } from '@/lib/prisma';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/permissions';

// GET /api/organizations
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('organization', 'view');

    const organizations = await prisma.organization.findMany({
      include: {
        owner: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
          },
        },
        children: true,
        _count: {
          select: {
            members: true,
          },
        },
      },
    });

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
    const existingOrg = await prisma.organization.findUnique({
      where: { slug },
    });

    if (existingOrg) {
      return new NextResponse('Organization with this slug already exists', { status: 400 });
    }

    // Create organization
    const organization = await prisma.organization.create({
      data: {
        name,
        slug,
        status,
        ownerId: session.user.id,
      },
    });

    return NextResponse.json(organization, { status: 201 });
  } catch (error) {
    console.error('[ORGANIZATIONS_POST]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
