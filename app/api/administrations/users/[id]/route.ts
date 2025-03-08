import { NextResponse, NextRequest } from 'next/server';
import { prisma } from '@/lib/prisma';
import { hash } from 'bcryptjs';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/permissions';

// GET /api/users/[id]
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('user', 'view');

    const { id } = await params;

    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        phone: true,
        avatar: true,
        userRoles: {
          select: {
            role: {
              select: {
                id: true,
                name: true,
                description: true,
              },
            },
          },
        },
        status: true,
        emailVerified: true,
        createdAt: true,
        updatedAt: true,
        memberships: {
          include: {
            organization: true,
            role: true,
          },
        },
      },
    });

    if (!user) {
      return new NextResponse('User not found', { status: 404 });
    }

    return NextResponse.json(user);
  } catch (error) {
    console.error('[USER_GET]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// PUT /api/users/[id]
export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('user', 'edit');

    const { id } = await params;
    const body = await request.json();
    const { email, password, firstName, lastName, phone, roleIds, status } = body;

    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { id },
    });

    if (!existingUser) {
      return new NextResponse('User not found', { status: 404 });
    }

    // If email is being changed, check if new email is already in use
    if (email && email !== existingUser.email) {
      const emailInUse = await prisma.user.findUnique({
        where: { email },
      });

      if (emailInUse) {
        return new NextResponse('Email already in use', { status: 400 });
      }
    }

    // Prepare update data
    const updateData: any = {
      ...(email && { email }),
      ...(firstName && { firstName }),
      ...(lastName && { lastName }),
      ...(phone && { phone }),
      ...(status && { status }),
    };

    // If password is provided, hash it
    if (password) {
      updateData.password = await hash(password, 12);
    }

    const updatedUser = await prisma.$transaction(async (tx) => {
      const user = await tx.user.update({
        where: { id },
        data: updateData,
      });
      
      if (roleIds && roleIds.length > 0) {
        await tx.userRole.deleteMany({
          where: { userId: id },
        });
        
        await Promise.all(
          roleIds.map((roleId: string) =>
            tx.userRole.create({
              data: {
                userId: id,
                roleId,
              },
            })
          )
        );
      }
      
      return tx.user.findUnique({
        where: { id },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          phone: true,
          avatar: true,
          userRoles: {
            select: {
              role: {
                select: {
                  id: true,
                  name: true,
                  description: true,
                },
              },
            },
          },
          status: true,
          emailVerified: true,
          createdAt: true,
          updatedAt: true,
          memberships: {
            include: {
              organization: true,
              role: true,
            },
          },
        },
      });
    });

    return NextResponse.json(updatedUser);
  } catch (error) {
    console.error('[USER_PUT]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// DELETE /api/users/[id]
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('user', 'delete');

    const { id } = await params;

    // Check if user exists
    const user = await prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      return new NextResponse('User not found', { status: 404 });
    }

    // Delete user
    await prisma.user.delete({
      where: { id },
    });

    return NextResponse.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('[USER_DELETE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
