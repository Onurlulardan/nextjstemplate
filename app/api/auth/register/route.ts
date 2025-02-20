import { NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { prisma } from '@/lib/prisma';
import { generateSlug } from '@/lib/utils/slug';

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

    // Create user and their organization in a transaction
    const result = await prisma.$transaction(async (prisma) => {
      // 1. Create the user
      const user = await prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          firstName,
          lastName,
          phone,
          role: 'ADMIN', // First user gets ADMIN role
        },
      });

      // 2. Create their organization
      const orgName = firstName ? `${firstName}'s Organization` : `New Organization`;
      const organization = await prisma.organization.create({
        data: {
          name: orgName,
          slug: generateSlug(orgName),
          owner: {
            connect: {
              id: user.id,
            },
          },
        },
      });

      // 3. Create owner role
      const ownerRole = await prisma.role.create({
        data: {
          name: 'Super Admin',
          description: 'Full administrative rights',
          isDefault: true,
          organization: {
            connect: {
              id: organization.id,
            },
          },
        },
      });

      // 4. Create organization member with owner role
      const member = await prisma.organizationMember.create({
        data: {
          organization: {
            connect: {
              id: organization.id,
            },
          },
          user: {
            connect: {
              id: user.id,
            },
          },
          role: {
            connect: {
              id: ownerRole.id,
            },
          },
        },
      });

      return { user, organization, member };
    });

    return NextResponse.json({
      user: {
        email: result.user.email,
        firstName: result.user.firstName,
        lastName: result.user.lastName,
      },
      organization: {
        name: result.organization.name,
        slug: result.organization.slug,
      },
    });
  } catch (error) {
    console.error('Registration error:', error);
    return new NextResponse('Internal Server Error', { status: 500 });
  }
}
