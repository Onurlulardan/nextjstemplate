import 'dotenv/config';
import knex from './index.js';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

const SUPER_ADMIN_MAIL = process.env.SUPER_ADMIN_MAIL || 'superadmin@superadmin.com';
const SUPER_ADMIN_FIRSTNAME = process.env.SUPER_ADMIN_FIRSTNAME || 'Super';
const SUPER_ADMIN_LASTNAME = process.env.SUPER_ADMIN_LASTNAME || 'Admin';
const SUPER_ADMIN_PASSWORD = process.env.SUPER_ADMIN_PASSWORD || '0ZzfqAxK!';

async function createDefaultResources() {
  const defaultResources = [
    { name: 'ALL', slug: '*', description: 'All resources (wildcard)' },
    { name: 'ORGANIZATION', slug: 'organization', description: 'Organization management' },
    { name: 'USER', slug: 'user', description: 'User management' },
    { name: 'ROLE', slug: 'role', description: 'Role management' },
    { name: 'PERMISSION', slug: 'permission', description: 'Permission management' },
    { name: 'SECURITY LOG', slug: 'security-log', description: 'Security logs management' },
  ];
  const resources = [];
  for (const resource of defaultResources) {
    let existing = await knex('Resource').where({ slug: resource.slug }).first();
    if (existing) {
      await knex('Resource').where({ slug: resource.slug }).update(resource);
      existing = await knex('Resource').where({ slug: resource.slug }).first();
      resources.push(existing);
    } else {
      const [created] = await knex('Resource').insert({ ...resource, id: crypto.randomUUID() }).returning('*');
      resources.push(created);
    }
  }
  console.log('✅ Default resources created');
  return resources;
}

async function createDefaultActions() {
  const defaultActions = [
    { name: 'VIEW', slug: 'view', description: 'Permission to view' },
    { name: 'CREATE', slug: 'create', description: 'Permission to create' },
    { name: 'EDIT', slug: 'edit', description: 'Permission to edit' },
    { name: 'DELETE', slug: 'delete', description: 'Permission to delete' },
    { name: 'MANAGE', slug: 'manage', description: 'Full management permission' },
  ];
  const actions = [];
  for (const action of defaultActions) {
    let existing = await knex('Action').where({ slug: action.slug }).first();
    if (existing) {
      await knex('Action').where({ slug: action.slug }).update(action);
      existing = await knex('Action').where({ slug: action.slug }).first();
      actions.push(existing);
    } else {
      const [created] = await knex('Action').insert({ ...action, id: crypto.randomUUID() }).returning('*');
      actions.push(created);
    }
  }
  console.log('✅ Default actions created');
  return actions;
}

async function createDefaultRoles() {
  const defaultRoles = [
    { name: 'ADMIN', description: 'Full system access', isDefault: false },
    { name: 'ORGANIZATION ADMIN', description: 'Full organization access', isDefault: false },
    { name: 'MEMBER', description: 'Basic member access', isDefault: true },
  ];
  const roles = [];
  for (const role of defaultRoles) {
    let existing = await knex('Role').where({ name: role.name }).first();
    if (existing) {
      await knex('Role').where({ name: role.name }).update(role);
      existing = await knex('Role').where({ name: role.name }).first();
      roles.push(existing);
    } else {
      const [created] = await knex('Role').insert({ ...role, id: crypto.randomUUID() }).returning('*');
      roles.push(created);
    }
  }
  console.log('✅ Default roles created');
  return roles;
}

async function createSuperAdmin() {
  const hashedPassword = await bcrypt.hash(SUPER_ADMIN_PASSWORD, 10);
  let existing = await knex('User').where({ email: SUPER_ADMIN_MAIL }).first();
  if (existing) {
    await knex('User').where({ email: SUPER_ADMIN_MAIL }).update({
      password: hashedPassword,
      firstName: SUPER_ADMIN_FIRSTNAME,
      lastName: SUPER_ADMIN_LASTNAME,
      status: 'ACTIVE',
      emailVerified: true,
    });
    existing = await knex('User').where({ email: SUPER_ADMIN_MAIL }).first();
    console.log('✅ Super Admin updated');
    return existing;
  } else {
    const [superAdmin] = await knex('User').insert({
      id: crypto.randomUUID(),
      email: SUPER_ADMIN_MAIL,
      password: hashedPassword,
      firstName: SUPER_ADMIN_FIRSTNAME,
      lastName: SUPER_ADMIN_LASTNAME,
      status: 'ACTIVE',
      emailVerified: true,
    }).returning('*');
    console.log('✅ Super Admin created');
    return superAdmin;
  }
}

async function createOrganizations(superAdmin: any) {
  let mainOrganization = await knex('Organization').where({ slug: 'main-organization' }).first();
  if (mainOrganization) {
    await knex('Organization').where({ slug: 'main-organization' }).update({
      name: 'Main Organization',
      status: 'ACTIVE',
      ownerId: superAdmin.id,
    });
    mainOrganization = await knex('Organization').where({ slug: 'main-organization' }).first();
  } else {
    [mainOrganization] = await knex('Organization').insert({
      id: crypto.randomUUID(),
      name: 'Main Organization',
      slug: 'main-organization',
      status: 'ACTIVE',
      ownerId: superAdmin.id,
    }).returning('*');
  }
  let childOrganization = await knex('Organization').where({ slug: 'child-organization' }).first();
  if (childOrganization) {
    await knex('Organization').where({ slug: 'child-organization' }).update({
      name: 'Child Organization',
      status: 'ACTIVE',
      parentId: mainOrganization.id,
      ownerId: superAdmin.id,
    });
    childOrganization = await knex('Organization').where({ slug: 'child-organization' }).first();
  } else {
    [childOrganization] = await knex('Organization').insert({
      id: crypto.randomUUID(),
      name: 'Child Organization',
      slug: 'child-organization',
      status: 'ACTIVE',
      parentId: mainOrganization.id,
      ownerId: superAdmin.id,
    }).returning('*');
  }
  console.log('✅ Organizations created');
  return { mainOrganization, childOrganization };
}

async function assignSuperAdminToOrganization(superAdmin: any, roles: any[], mainOrganization: any) {
  const adminRole = roles.find((r) => r.name === 'ADMIN');
  if (!adminRole) throw new Error('ADMIN role not found');
  await knex('UserRole').where({ userId: superAdmin.id }).del();
  await knex('UserRole').insert({ id: crypto.randomUUID(), userId: superAdmin.id, roleId: adminRole.id });
  const orgAdminRole = roles.find((r) => r.name === 'ORGANIZATION ADMIN');
  if (orgAdminRole) {
    await knex('OrganizationMember').where({ userId: superAdmin.id, organizationId: mainOrganization.id }).del();
    await knex('OrganizationMember').insert({ id: crypto.randomUUID(), userId: superAdmin.id, organizationId: mainOrganization.id, roleId: orgAdminRole.id });
  }
  console.log('✅ Super Admin assigned to organization');
}

async function createSuperAdminPermissions(superAdmin: any, resources: any[], actions: any[]) {
  await knex('Permission').where({ userId: superAdmin.id }).del();
  const wildcardResource = resources.find((r) => r.slug === '*');
  if (wildcardResource) {
    const [permission] = await knex('Permission').insert({
      id: crypto.randomUUID(),
      userId: superAdmin.id,
      resourceId: wildcardResource.id,
      target: 'USER',
    }).returning('*');
    for (const action of actions) {
      await knex('PermissionAction').insert({ id: crypto.randomUUID(), permissionId: permission.id, actionId: action.id });
    }
  }
  console.log('✅ Super Admin permissions created');
}

async function createDefaultRolePermissions(roles: any[], resources: any[], actions: any[]) {
  const orgAdminRole = roles.find((r) => r.name === 'ORGANIZATION ADMIN');
  if (orgAdminRole) {
    for (const resource of resources) {
      const [permission] = await knex('Permission').insert({
        id: crypto.randomUUID(),
        roleId: orgAdminRole.id,
        resourceId: resource.id,
        target: 'ROLE',
      }).returning('*');
      for (const action of actions) {
        await knex('PermissionAction').insert({ id: crypto.randomUUID(), permissionId: permission.id, actionId: action.id });
      }
    }
  }
  const memberRole = roles.find((r) => r.name === 'MEMBER');
  if (memberRole) {
    const viewableResources = ['security-log'];
    const viewAction = actions.find((a) => a.slug === 'view');
    for (const resourceSlug of viewableResources) {
      const resource = resources.find((r) => r.slug === resourceSlug);
      if (resource && viewAction) {
        const [permission] = await knex('Permission').insert({
          id: crypto.randomUUID(),
          roleId: memberRole.id,
          resourceId: resource.id,
          target: 'ROLE',
        }).returning('*');
        await knex('PermissionAction').insert({ id: crypto.randomUUID(), permissionId: permission.id, actionId: viewAction.id });
      }
    }
  }
  console.log('✅ Default role permissions created');
}

async function main() {
  try {
    const resources = await createDefaultResources();
    const actions = await createDefaultActions();
    const roles = await createDefaultRoles();
    const superAdmin = await createSuperAdmin();
    const { mainOrganization, childOrganization } = await createOrganizations(superAdmin);
    await assignSuperAdminToOrganization(superAdmin, roles, mainOrganization);
    await createSuperAdminPermissions(superAdmin, resources, actions);
    await createDefaultRolePermissions(roles, resources, actions);
    console.log('✅ Seed completed successfully');
    process.exit(0);
  } catch (error) {
    console.error('❌ Seed error:', error);
    process.exit(1);
  }
}

main();
