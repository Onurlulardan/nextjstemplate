import { NextResponse, NextRequest } from 'next/server';
import { prisma } from '@/lib/prisma';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/permissions';

// GET /api/roles/[id]
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('role', 'view');

    const { id } = await params;

    const role = await prisma.role.findUnique({
      where: { id },
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
        userRoles: {
          include: {
            user: {
              select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
              },
            },
          },
        },
      },
    });

    if (!role) {
      return new NextResponse('Role not found', { status: 404 });
    }

    return NextResponse.json(role);
  } catch (error) {
    console.error('[ROLE_GET]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// PUT /api/roles/[id]
export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('role', 'edit');

    const { id } = await params;
    const body = await request.json();
    const { name, description, isDefault } = body;

    if (!name && description === undefined && isDefault === undefined) {
      return new NextResponse('No fields to update', { status: 400 });
    }

    // Check if role exists
    const existingRole = await prisma.role.findUnique({
      where: { id },
      include: {
        organization: true,
      },
    });

    if (!existingRole) {
      return new NextResponse('Role not found', { status: 404 });
    }

    // If name is being changed, check if new name is already in use in the same organization
    if (name && name !== existingRole.name) {
      const nameExists = await prisma.role.findFirst({
        where: {
          name,
          organizationId: existingRole.organizationId,
          id: { not: id }, // Exclude current role
        },
      });

      if (nameExists) {
        return new NextResponse('Role with this name already exists in the organization', {
          status: 400,
        });
      }
    }

    if (isDefault === true) {
      const updatedRole = await prisma.$transaction(async (tx) => {
        if (existingRole.organizationId) {
          await tx.role.updateMany({
            where: {
              organizationId: existingRole.organizationId,
              isDefault: true,
              id: { not: id },
            },
            data: {
              isDefault: false,
            },
          });
        } else {
          await tx.role.updateMany({
            where: {
              organizationId: null,
              isDefault: true,
              id: { not: id },
            },
            data: {
              isDefault: false,
            },
          });
        }

        return await tx.role.update({
          where: { id },
          data: {
            ...(name && { name }),
            ...(description !== undefined && { description }),
            isDefault: true,
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
      });

      return NextResponse.json(updatedRole);
    } else {
      const updatedRole = await prisma.role.update({
        where: { id },
        data: {
          ...(name && { name }),
          ...(description !== undefined && { description }),
          ...(isDefault !== undefined && { isDefault }),
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

      return NextResponse.json(updatedRole);
    }
  } catch (error) {
    console.error('[ROLE_PUT]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// DELETE /api/roles/[id]
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('role', 'delete');

    const { id } = await params;

    // Check if role exists
    const role = await prisma.role.findUnique({
      where: { id },
      include: {
        _count: {
          select: {
            userRoles: true,
          },
        },
      },
    });

    if (!role) {
      return new NextResponse('Role not found', { status: 404 });
    }

    // Check if role has users
    if (role._count.userRoles > 0) {
      return new NextResponse(
        'Cannot delete role with assigned users. Remove users from this role first.',
        {
          status: 400,
        }
      );
    }

    // Delete role
    await prisma.role.delete({
      where: { id },
    });

    return new NextResponse(null, { status: 204 });
  } catch (error) {
    console.error('[ROLE_DELETE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
