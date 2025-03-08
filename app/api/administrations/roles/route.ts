import { NextResponse, NextRequest } from 'next/server';
import { prisma } from '@/lib/prisma';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/permissions';

// GET /api/roles
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('role', 'view');

    const roles = await prisma.role.findMany({
      include: {
        organization: {
          select: {
            id: true,
            name: true,
            slug: true,
          },
        },
        permissions: {
          include: {
            resource: true,
            actions: {
              include: {
                action: true,
              },
            },
          },
        },
        _count: {
          select: {
            members: true,
          },
        },
      },
    });

    return NextResponse.json(roles);
  } catch (error) {
    console.error('[ROLES_GET]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// POST /api/roles
export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('role', 'create');

    const body = await request.json();
    const { name, description, isDefault, organizationId } = body;

    if (!name) {
      return new NextResponse('Missing required fields', { status: 400 });
    }

    // Check if role with name already exists
    const existingRole = await prisma.role.findFirst({
      where: {
        name,
        organizationId,
      },
    });

    if (existingRole) {
      return new NextResponse('Role with this name already exists in the organization', {
        status: 400,
      });
    }

    // Create role
    const role = await prisma.role.create({
      data: {
        name,
        description,
        isDefault: isDefault || false,
        organizationId,
      },
      include: {
        organization: {
          select: {
            id: true,
            name: true,
            slug: true,
          },
        },
      },
    });

    return NextResponse.json(role, { status: 201 });
  } catch (error) {
    console.error('[ROLES_POST]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
