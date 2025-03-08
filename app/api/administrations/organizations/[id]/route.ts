import { NextResponse, NextRequest } from 'next/server';
import { prisma } from '@/lib/prisma';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/permissions';

// GET /api/organizations/[id]
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('organization', 'view');

    const { id } = await params;

    const organization = await prisma.organization.findUnique({
      where: { id },
      include: {
        owner: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
          },
        },
        members: {
          include: {
            user: {
              select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
              },
            },
            role: true,
          },
        },
        roles: true,
        parent: true,
        children: true,
      },
    });

    if (!organization) {
      return new NextResponse('Organization not found', { status: 404 });
    }

    return NextResponse.json(organization);
  } catch (error) {
    console.error('[ORGANIZATION_GET]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// PUT /api/organizations/[id]
export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('organization', 'edit');

    const { id } = await params;

    const body = await request.json();
    const { name, slug, status, parentId } = body;

    if (!name && !slug && !status && !parentId) {
      return new NextResponse('No fields to update', { status: 400 });
    }

    // Check if organization exists
    const existingOrg = await prisma.organization.findUnique({
      where: { id },
    });

    if (!existingOrg) {
      return new NextResponse('Organization not found', { status: 404 });
    }

    // Check if new slug is already taken
    if (slug && slug !== existingOrg.slug) {
      const slugExists = await prisma.organization.findUnique({
        where: { slug },
      });

      if (slugExists) {
        return new NextResponse('Organization with this slug already exists', {
          status: 400,
        });
      }
    }

    const updatedOrganization = await prisma.organization.update({
      where: { id },
      data: {
        name,
        slug,
        status: status as any,
        parentId,
      },
      include: {
        owner: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
          },
        },
      },
    });

    return NextResponse.json(updatedOrganization);
  } catch (error) {
    console.error('[ORGANIZATION_PUT]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// DELETE /api/organizations/[id]
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('organization', 'delete');

    const { id } = await params;

    // Check if organization exists
    const organization = await prisma.organization.findUnique({
      where: { id },
    });

    if (!organization) {
      return new NextResponse('Organization not found', { status: 404 });
    }

    // Check if user is the owner
    if (organization.ownerId !== session.user.id) {
      return new NextResponse('Only owner can delete organization', { status: 403 });
    }

    // Delete organization (cascade will handle related records)
    await prisma.organization.delete({
      where: { id },
    });

    return new NextResponse(null, { status: 204 });
  } catch (error) {
    console.error('[ORGANIZATION_DELETE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
