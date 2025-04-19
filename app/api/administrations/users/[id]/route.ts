import { NextResponse, NextRequest } from 'next/server';
import knex from '@/knex';
import { hash } from 'bcryptjs';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/server-permissions';

// GET /api/users/[id]
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('user', 'view');

    const { id } = await params;

    // Get user details
    const user = await knex('User')
      .where({ id })
      .first(
        'id',
        'email',
        'firstName',
        'lastName',
        'phone',
        'avatar',
        'status',
        'emailVerified',
        'createdAt',
        'updatedAt'
      );
      
    if (user) {
      // Get user roles
      const userRoles = await knex('UserRole')
        .where({ userId: id })
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
        .where({ userId: id })
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
    const existingUser = await knex('User')
      .where({ id })
      .first();

    if (!existingUser) {
      return new NextResponse('User not found', { status: 404 });
    }

    // If email is being changed, check if new email is already in use
    if (email && email !== existingUser.email) {
      const emailInUse = await knex('User')
        .where({ email })
        .first();

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
      updatedAt: knex.fn.now()
    };

    // If password is provided, hash it
    if (password) {
      updateData.password = await hash(password, 12);
    }

    const updatedUser = await knex.transaction(async (trx) => {
      // 1. Update user
      await trx('User')
        .where({ id })
        .update(updateData);
      
      // 2. Update roles if provided
      if (roleIds && roleIds.length > 0) {
        // Delete existing roles
        await trx('UserRole')
          .where({ userId: id })
          .delete();
        
        // Add new roles
        await Promise.all(
          roleIds.map((roleId: string) =>
            trx('UserRole')
              .insert({
                id: trx.raw('uuid_generate_v4()'),
                userId: id,
                roleId,
                createdAt: trx.fn.now(),
                updatedAt: trx.fn.now()
              })
          )
        );
      }
      
      // 3. Get updated user
      const user = await trx('User')
        .where({ id })
        .first(
          'id',
          'email',
          'firstName',
          'lastName',
          'phone',
          'avatar',
          'status',
          'emailVerified',
          'createdAt',
          'updatedAt'
        );
      
      // 4. Get user roles
      const userRoles = await trx('UserRole')
        .where({ userId: id })
        .join('Role', 'UserRole.roleId', 'Role.id')
        .select(
          'Role.id',
          'Role.name',
          'Role.description'
        );

      // 5. Get user memberships
      const memberships = await trx('OrganizationMember')
        .where({ userId: id })
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

      // 6. Format and return user
      return {
        ...user,
        userRoles: userRoles.map(role => ({
          role: {
            id: role.id,
            name: role.name,
            description: role.description
          }
        })),
        memberships: memberships.map(m => ({
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
        }))
      };
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
    const user = await knex('User')
      .where({ id })
      .first();

    if (!user) {
      return new NextResponse('User not found', { status: 404 });
    }

    // Delete user - using transaction to ensure all related records are deleted
    await knex.transaction(async (trx) => {
      // First delete related records
      await trx('UserRole').where({ userId: id }).delete();
      await trx('OrganizationMember').where({ userId: id }).delete();
      
      // Then delete the user
      await trx('User').where({ id }).delete();
    });

    return NextResponse.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('[USER_DELETE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
