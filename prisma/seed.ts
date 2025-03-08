import { PrismaClient, UserRole, UserStatus, PermissionTarget } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

const SUPER_ADMIN_MAIL = process.env.SUPER_ADMIN_MAIL || 'superadmin@superadmin.com';
const SUPER_ADMIN_FIRSTNAME = process.env.SUPER_ADMIN_FIRSTNAME || 'Super';
const SUPER_ADMIN_LASTNAME = process.env.SUPER_ADMIN_LASTNAME || 'Admin';
const SUPER_ADMIN_PASSWORD = process.env.SUPER_ADMIN_PASSWORD || '0ZzfqAxK!';

async function createDefaultResources() {
  const defaultResources = [
    {
      name: 'ALL',
      slug: '*',
      description: 'All resources (wildcard)',
    },
    {
      name: 'ORGANIZATION',
      slug: 'organization',
      description: 'Organization management',
    },
    {
      name: 'USER',
      slug: 'user',
      description: 'User management',
    },
    {
      name: 'ROLE',
      slug: 'role',
      description: 'Role management',
    },
    {
      name: 'PERMISSION',
      slug: 'permission',
      description: 'Permission management',
    },
    {
      name: 'SECURITY LOG',
      slug: 'security-log',
      description: 'Security logs management',
    },
  ];

  const resources = [];
  for (const resource of defaultResources) {
    const createdResource = await prisma.resource.upsert({
      where: { slug: resource.slug },
      update: resource,
      create: resource,
    });
    resources.push(createdResource);
  }

  console.log('✅ Default resources created');
  return resources;
}

async function createDefaultActions() {
  const defaultActions = [
    {
      name: 'VIEW',
      slug: 'view',
      description: 'Permission to view',
    },
    {
      name: 'CREATE',
      slug: 'create',
      description: 'Permission to create',
    },
    {
      name: 'EDIT',
      slug: 'edit',
      description: 'Permission to edit',
    },
    {
      name: 'DELETE',
      slug: 'delete',
      description: 'Permission to delete',
    },
    {
      name: 'MANAGE',
      slug: 'manage',
      description: 'Full management permission',
    },
  ];

  const actions = [];
  for (const action of defaultActions) {
    const createdAction = await prisma.action.upsert({
      where: { slug: action.slug },
      update: action,
      create: action,
    });
    actions.push(createdAction);
  }

  console.log('✅ Default actions created');
  return actions;
}

async function createDefaultRoles() {
  const defaultRoles = [
    {
      name: 'ADMIN',
      description: 'Full system access',
      isDefault: false,
    },
    {
      name: 'ORGANIZATION ADMIN',
      description: 'Full organization access',
      isDefault: false,
    },
    {
      name: 'MEMBER',
      description: 'Basic member access',
      isDefault: true,
    },
  ];

  const roles = [];
  for (const role of defaultRoles) {
    const createdRole = await prisma.role.upsert({
      where: { name: role.name },
      update: role,
      create: role,
    });
    roles.push(createdRole);
  }

  console.log('✅ Default roles created');
  return roles;
}

async function createSuperAdmin() {
  // Create super admin user
  const hashedPassword = await bcrypt.hash(SUPER_ADMIN_PASSWORD, 10);

  const superAdmin = await prisma.user.upsert({
    where: { email: SUPER_ADMIN_MAIL },
    update: {
      password: hashedPassword,
    },
    create: {
      email: SUPER_ADMIN_MAIL,
      password: hashedPassword,
      firstName: SUPER_ADMIN_FIRSTNAME,
      lastName: SUPER_ADMIN_LASTNAME,
      status: UserStatus.ACTIVE,
      emailVerified: true,
    },
  });

  console.log('✅ Super Admin created');
  return superAdmin;
}

async function createOrganizations(superAdmin: any) {
  // Create main organization
  const mainOrganization = await prisma.organization.upsert({
    where: { slug: 'main-organization' },
    update: {
      name: 'Main Organization',
      status: 'ACTIVE',
      ownerId: superAdmin.id,
    },
    create: {
      name: 'Main Organization',
      slug: 'main-organization',
      status: 'ACTIVE',
      ownerId: superAdmin.id,
    },
  });

  // Create child organization
  const childOrganization = await prisma.organization.upsert({
    where: { slug: 'child-organization' },
    update: {
      name: 'Child Organization',
      status: 'ACTIVE',
      parentId: mainOrganization.id,
      ownerId: superAdmin.id,
    },
    create: {
      name: 'Child Organization',
      slug: 'child-organization',
      status: 'ACTIVE',
      parentId: mainOrganization.id,
      ownerId: superAdmin.id,
    },
  });

  console.log('✅ Organizations created');
  return { mainOrganization, childOrganization };
}

async function assignSuperAdminToOrganization(superAdmin: any, roles: any[], mainOrganization: any) {
  // Find the ADMIN role
  const adminRole = roles.find((r) => r.name === 'ADMIN');
  if (!adminRole) {
    throw new Error('ADMIN role not found');
  }

  await prisma.userRole.deleteMany({
    where: { userId: superAdmin.id },
  });

  await prisma.userRole.create({
    data: {
      userId: superAdmin.id,
      roleId: adminRole.id,
    },
  });

  // Create organization membership for super admin
  const orgAdminRole = roles.find((r) => r.name === 'ORGANIZATION ADMIN');
  if (orgAdminRole) {
    // Delete any existing memberships first
    await prisma.organizationMember.deleteMany({
      where: {
        userId: superAdmin.id,
        organizationId: mainOrganization.id,
      },
    });

    // Create new membership
    await prisma.organizationMember.create({
      data: {
        userId: superAdmin.id,
        organizationId: mainOrganization.id,
        roleId: orgAdminRole.id,
      },
    });
  }

  console.log('✅ Super Admin assigned to organization');
  return superAdmin;
}

async function createSuperAdminPermissions(superAdmin: any, resources: any[], actions: any[]) {
  await prisma.permission.deleteMany({
    where: {
      userId: superAdmin.id,
    },
  });

  const wildcardResource = resources.find((r) => r.slug === '*');
  if (wildcardResource) {
    const permission = await prisma.permission.create({
      data: {
        userId: superAdmin.id,
        resourceId: wildcardResource.id,
        target: PermissionTarget.USER,
      },
    });

    // Create PermissionAction entries for each action
    for (const action of actions) {
      await prisma.permissionAction.create({
        data: {
          permissionId: permission.id,
          actionId: action.id,
        },
      });
    }
  }

  console.log('✅ Super Admin permissions created');
}

async function createDefaultRolePermissions(roles: any[], resources: any[], actions: any[]) {
  // Permission for Organization Admin role
  const orgAdminRole = roles.find((r) => r.name === 'ORGANIZATION ADMIN');
  if (orgAdminRole) {
    for (const resource of resources) {
      const permission = await prisma.permission.create({
        data: {
          roleId: orgAdminRole.id,
          resourceId: resource.id,
          target: PermissionTarget.ROLE,
        },
      });

      // Add all actions for each resource
      for (const action of actions) {
        await prisma.permissionAction.create({
          data: {
            permissionId: permission.id,
            actionId: action.id,
          },
        });
      }
    }
  }

  // Permission for Member role
  const memberRole = roles.find((r) => r.name === 'MEMBER');
  if (memberRole) {
    const viewableResources = ['security-log'];
    const viewAction = actions.find((a) => a.slug === 'view');

    for (const resourceSlug of viewableResources) {
      const resource = resources.find((r) => r.slug === resourceSlug);
      if (resource && viewAction) {
        const permission = await prisma.permission.create({
          data: {
            roleId: memberRole.id,
            resourceId: resource.id,
            target: PermissionTarget.ROLE,
          },
        });

        await prisma.permissionAction.create({
          data: {
            permissionId: permission.id,
            actionId: viewAction.id,
          },
        });
      }
    }
  }

  console.log('✅ Default role permissions created');
}

async function main() {
  try {
    // Create resources and actions first
    const resources = await createDefaultResources();
    const actions = await createDefaultActions();

    // Create default roles
    const roles = await createDefaultRoles();

    // Create super admin user first
    const superAdmin = await createSuperAdmin();

    // Create organizations with super admin as owner
    const { mainOrganization, childOrganization } = await createOrganizations(superAdmin);

    // Assign super admin to organization with roles
    await assignSuperAdminToOrganization(superAdmin, roles, mainOrganization);

    // Create permissions for super admin
    await createSuperAdminPermissions(superAdmin, resources, actions);

    // Create default role permissions
    await createDefaultRolePermissions(roles, resources, actions);

    console.log('✅ Seed completed successfully');
  } catch (error) {
    console.error('❌ Seed error:', error);
    throw error;
  }
}

main()
  .catch((e) => {
    console.error('❌ Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
