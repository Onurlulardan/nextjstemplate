import { NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { prisma } from '@/lib/prisma';

export async function POST(req: Request) {
  try {
    const { email, password, firstName, lastName, phone } = await req.json();

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return new NextResponse('Email already exists', { status: 400 });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user and assign default role
    const result = await prisma.$transaction(async (prisma) => {
      // 1. Create the user
      const user = await prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          firstName,
          lastName,
          phone,
        },
      });

      // 2. Find default role
      const defaultRole = await prisma.role.findFirst({
        where: {
          isDefault: true,
        },
      });

      // 3. If default role exists, assign it to the user
      if (defaultRole) {
        await prisma.userRole.create({
          data: {
            user: {
              connect: {
                id: user.id,
              },
            },
            role: {
              connect: {
                id: defaultRole.id,
              },
            },
          },
        });
      }

      return { user, defaultRole };
    });

    return NextResponse.json({
      user: {
        email: result.user.email,
        firstName: result.user.firstName,
        lastName: result.user.lastName,
      },
      role: result.defaultRole
        ? {
            name: result.defaultRole.name,
            isDefault: result.defaultRole.isDefault,
          }
        : null,
    });
  } catch (error) {
    console.error('Registration error:', error);
    return new NextResponse('Internal Server Error', { status: 500 });
  }
}
