import { NextResponse, NextRequest } from 'next/server';
import knex from '@/knex';
import { hash } from 'bcryptjs';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/server-permissions';

// GET /api/users
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('user', 'view');

    // Get users with their roles
    const users = await knex('User')
      .select(
        'User.id',
        'User.email',
        'User.firstName',
        'User.lastName',
        'User.phone',
        'User.avatar',
        'User.status',
        'User.emailVerified',
        'User.createdAt',
        'User.updatedAt'
      );

    // For each user, get their roles
    for (const user of users) {
      // Get user roles
      const userRoles = await knex('UserRole')
        .where({ userId: user.id })
        .join('Role', 'UserRole.roleId', 'Role.id')
        .select(
          'Role.id',
          'Role.name',
          'Role.description'
        );

      user.userRoles = userRoles.map(role => ({
        role: {
          id: role.id,
          name: role.name,
          description: role.description
        }
      }));

      // Get user memberships
      const memberships = await knex('OrganizationMember')
        .where({ userId: user.id })
        .join('Organization', 'OrganizationMember.organizationId', 'Organization.id')
        .leftJoin('Role', 'OrganizationMember.roleId', 'Role.id')
        .select(
          'OrganizationMember.id as membershipId',
          'Organization.id as organizationId',
          'Organization.name as organizationName',
          'Organization.slug as organizationSlug',
          'Role.id as roleId',
          'Role.name as roleName',
          'Role.description as roleDescription'
        );

      user.memberships = memberships.map(m => ({
        id: m.membershipId,
        organization: {
          id: m.organizationId,
          name: m.organizationName,
          slug: m.organizationSlug
        },
        role: m.roleId ? {
          id: m.roleId,
          name: m.roleName,
          description: m.roleDescription
        } : null
      }));
    }

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
    const existingUser = await knex('User')
      .where({ email })
      .first();

    if (existingUser) {
      return new NextResponse('User already exists', { status: 400 });
    }

    // Hash password
    const hashedPassword = await hash(password, 12);

    // Use transaction for creating user and assigning roles
    const user = await knex.transaction(async (trx) => {
      // 1. Create the user
      const insertResult = await trx('User')
        .insert({
          id: trx.raw('uuid_generate_v4()'),
          email,
          password: hashedPassword,
          firstName,
          lastName,
          phone,
          status: status || 'ACTIVE',
          createdAt: trx.fn.now(),
          updatedAt: trx.fn.now()
        })
        .returning('*');

      const newUser = insertResult[0];

      // 2. Assign roles if provided
      if (roleIds && roleIds.length > 0) {
        await Promise.all(
          roleIds.map((roleId: string) =>
            trx('UserRole')
              .insert({
                id: trx.raw('uuid_generate_v4()'),
                userId: newUser.id,
                roleId,
                createdAt: trx.fn.now(),
                updatedAt: trx.fn.now()
              })
          )
        );
      }

      // 3. Get user roles
      const userRoles = await trx('UserRole')
        .where({ userId: newUser.id })
        .join('Role', 'UserRole.roleId', 'Role.id')
        .select(
          'Role.id',
          'Role.name',
          'Role.description'
        );

      // 4. Format user with roles
      const formattedUser = {
        ...newUser,
        userRoles: userRoles.map(role => ({
          role: {
            id: role.id,
            name: role.name,
            description: role.description
          }
        })),
        memberships: [] // New user has no memberships yet
      };

      return formattedUser;
    });

    return NextResponse.json(user, { status: 201 });
  } catch (error) {
    console.error('[USERS_POST]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
