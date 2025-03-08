import { NextResponse, NextRequest } from 'next/server';
import { prisma } from '@/lib/prisma';
import { hash } from 'bcryptjs';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/permissions';

// GET /api/users
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('user', 'view');

    const users = await prisma.user.findMany({
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

    return NextResponse.json(users);
  } catch (error) {
    console.error('[USERS_GET]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}

// POST /api/users
export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('user', 'create');

    const body = await request.json();
    const { email, password, firstName, lastName, phone, roleIds, status } = body;

    if (!email || !password) {
      return new NextResponse('Missing required fields', { status: 400 });
    }

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return new NextResponse('User already exists', { status: 400 });
    }

    // Hash password
    const hashedPassword = await hash(password, 12);

    const user = await prisma.$transaction(async (tx) => {
      const newUser = await tx.user.create({
        data: {
          email,
          password: hashedPassword,
          firstName,
          lastName,
          phone,
          status: status || 'ACTIVE',
        },
      });
      
      if (roleIds && roleIds.length > 0) {
        await Promise.all(
          roleIds.map((roleId: string) =>
            tx.userRole.create({
              data: {
                userId: newUser.id,
                roleId,
              },
            })
          )
        );
      }
      
      return await tx.user.findUnique({
        where: { id: newUser.id },
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

    return NextResponse.json(user, { status: 201 });
  } catch (error) {
    console.error('[USERS_POST]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
