import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { prisma } from '@/lib/prisma';
import { authOptions } from '@/lib/auth/auth-options';
import bcrypt from 'bcryptjs';
import { requirePermission } from '@/lib/auth/permissions';

export async function GET(request: Request) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('profile', 'view');

    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        userRoles: true,
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
        memberships: {
          include: {
            organization: true,
            role: {
              include: {
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
              },
            },
          },
        },
      },
    });

    if (!user) {
      return new NextResponse('User not found', { status: 404 });
    }

    return NextResponse.json(user);
  } catch (error) {
    console.error('[PROFILE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

export async function PUT(request: Request) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('profile', 'edit');

    const { email, firstName, lastName, currentPassword, newPassword } = await request.json();

    // Get current user
    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        password: true,
        userRoles: true,
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
        memberships: {
          include: {
            organization: true,
            role: {
              include: {
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
              },
            },
          },
        },
      },
    });

    if (!user) {
      return new NextResponse('User not found', { status: 404 });
    }

    // Check if email is taken
    if (email && email !== user.email) {
      const existingUser = await prisma.user.findUnique({
        where: { email },
      });

      if (existingUser) {
        return new NextResponse('Email already taken', { status: 400 });
      }
    }

    // Verify current password if changing password
    if (newPassword) {
      if (!currentPassword) {
        return new NextResponse('Current password is required', { status: 400 });
      }

      const isPasswordValid = await bcrypt.compare(currentPassword, user.password!);
      if (!isPasswordValid) {
        return new NextResponse('Current password is incorrect', { status: 400 });
      }
    }

    // Update user
    const updatedUser = await prisma.user.update({
      where: { id: session.user.id },
      data: {
        ...(email && { email }),
        ...(firstName && { firstName }),
        ...(lastName && { lastName }),
        ...(newPassword && { password: await bcrypt.hash(newPassword, 10) }),
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        userRoles: true,
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
        memberships: {
          include: {
            organization: true,
            role: {
              include: {
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
              },
            },
          },
        },
      },
    });

    return NextResponse.json(updatedUser);
  } catch (error) {
    console.error('[PROFILE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
