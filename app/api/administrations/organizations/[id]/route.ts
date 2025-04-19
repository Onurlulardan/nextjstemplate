import { NextResponse, NextRequest } from 'next/server';
import knex from '@/knex';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth/auth-options';
import { requirePermission } from '@/lib/auth/server-permissions';

// GET /api/organizations/[id]
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    await requirePermission('organization', 'view');

    const { id } = await params;

    // Get organization details
    const organization = await knex('Organization')
      .where({ id })
      .first(
        'id',
        'name',
        'slug',
        'status',
        'ownerId',
        'parentId',
        'createdAt',
        'updatedAt'
      );

    if (organization) {
      // Get owner information
      const owner = await knex('User')
        .where({ id: organization.ownerId })
        .select('id', 'email', 'firstName', 'lastName')
        .first();
      organization.owner = owner || null;

      // Get members with user and role information
      const members = await knex('OrganizationMember')
        .where({ organizationId: id })
        .select(
          'OrganizationMember.id',
          'OrganizationMember.userId',
          'OrganizationMember.roleId',
          'OrganizationMember.createdAt',
          'OrganizationMember.updatedAt'
        );

      // For each member, get user and role details
      organization.members = [];
      for (const member of members) {
        const user = await knex('User')
          .where({ id: member.userId })
          .select('id', 'email', 'firstName', 'lastName')
          .first();

        let role = null;
        if (member.roleId) {
          role = await knex('Role')
            .where({ id: member.roleId })
            .first();
        }

        organization.members.push({
          ...member,
          user,
          role
        });
      }

      // Get roles for this organization
      const roles = await knex('Role')
        .where({ organizationId: id })
        .select('*');
      organization.roles = roles;

      // Get parent organization if exists
      if (organization.parentId) {
        const parent = await knex('Organization')
          .where({ id: organization.parentId })
          .first();
        organization.parent = parent || null;
      } else {
        organization.parent = null;
      }

      // Get children organizations
      const children = await knex('Organization')
        .where({ parentId: id })
        .select('*');
      organization.children = children;
    }

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
    const existingOrg = await knex('Organization')
      .where({ id })
      .first();

    if (!existingOrg) {
      return new NextResponse('Organization not found', { status: 404 });
    }

    // Check if new slug is already taken
    if (slug && slug !== existingOrg.slug) {
      const slugExists = await knex('Organization')
        .where({ slug })
        .first();

      if (slugExists) {
        return new NextResponse('Organization with this slug already exists', {
          status: 400,
        });
      }
    }

    // Update organization
    await knex('Organization')
      .where({ id })
      .update({
        ...(name && { name }),
        ...(slug && { slug }),
        ...(status && { status }),
        ...(parentId !== undefined && { parentId }),
        updatedAt: knex.fn.now()
      });

    // Get updated organization
    const updatedOrganization = await knex('Organization')
      .where({ id })
      .first();

    // Get owner information
    if (updatedOrganization) {
      const owner = await knex('User')
        .where({ id: updatedOrganization.ownerId })
        .select('id', 'email', 'firstName', 'lastName')
        .first();
      updatedOrganization.owner = owner || null;
    }

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
    const organization = await knex('Organization')
      .where({ id })
      .first();

    if (!organization) {
      return new NextResponse('Organization not found', { status: 404 });
    }

    // Check if user is the owner
    if (organization.ownerId !== session.user.id) {
      return new NextResponse('Only owner can delete organization', { status: 403 });
    }

    // Delete organization (cascade will handle related records through foreign key constraints)
    await knex('Organization')
      .where({ id })
      .delete();

    return new NextResponse(null, { status: 204 });
  } catch (error) {
    console.error('[ORGANIZATION_DELETE]', error);
    return new NextResponse('Internal Error', { status: 500 });
  }
}
