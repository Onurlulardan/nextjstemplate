import { NextAuthKnexAdapter } from '@/knex/adapters/nextauth-knex-adapter';
import knex from '@/knex';
import { NextAuthOptions } from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import bcrypt from 'bcryptjs';
import { UserStatus, PermissionTarget, Permission } from './types';

export const authOptions: NextAuthOptions = {
  adapter: NextAuthKnexAdapter(knex),
  session: {
    strategy: 'jwt',
    maxAge: Number(process.env.NEXTAUTH_SESSION_MAX_AGE) || 7 * 24 * 60 * 60, // 7 days
    updateAge: Number(process.env.NEXTAUTH_SESSION_UPDATE_AGE) || 60 * 60, // 1 hour
  },
  pages: {
    signIn: '/auth/login',
    newUser: '/auth/register',
    error: '/auth/error',
  },
  providers: [
    CredentialsProvider({
      name: 'Credentials',
      credentials: {
        email: { label: 'Email', type: 'text' },
        password: { label: 'Password', type: 'password' },
      },
      // cast request to any to avoid undefined-header errors
      async authorize(credentials, request: any) {
        const headers = request.headers || {};
        const ipAddress = (headers['x-forwarded-for'] as string)?.split(',')[0] || '0.0.0.0';
        const userAgent = (headers['user-agent'] as string) || 'Unknown';

        // missing credentials
        if (!credentials?.email || !credentials?.password) {
          await knex('SecurityLog')
            .insert({
              email: credentials?.email || '',
              ipAddress: ipAddress === '::1' ? '127.0.0.1' : ipAddress,
              userAgent,
              status: 'FAILED',
              type: 'LOGIN',
              message: 'Missing credentials',
              createdAt: knex.fn.now(),
            })
            .catch(console.error);
          throw new Error('Please provide both email and password');
        }

        // fetch user
        const user = await knex('User')
          .whereRaw('LOWER(email) = ?', [credentials.email.toLowerCase()])
          .first();
        if (!user) {
          await knex('SecurityLog')
            .insert({
              email: credentials.email.toLowerCase(),
              ipAddress: ipAddress === '::1' ? '127.0.0.1' : ipAddress,
              userAgent,
              status: 'FAILED',
              type: 'LOGIN',
              message: 'Invalid credentials',
              createdAt: knex.fn.now(),
            })
            .catch(console.error);
          throw new Error('Invalid email or password');
        }

        // check password
        const valid = await bcrypt.compare(credentials.password, user.password);
        if (!valid) {
          await knex('SecurityLog')
            .insert({
              email: credentials.email.toLowerCase(),
              ipAddress: ipAddress === '::1' ? '127.0.0.1' : ipAddress,
              userAgent,
              status: 'FAILED',
              type: 'LOGIN',
              message: 'Invalid credentials',
              createdAt: knex.fn.now(),
            })
            .catch(console.error);
          throw new Error('Invalid email or password');
        }

        // inactive account
        if (user.status !== UserStatus.ACTIVE) {
          await knex('SecurityLog')
            .insert({
              userId: user.id,
              email: user.email,
              ipAddress: ipAddress === '::1' ? '127.0.0.1' : ipAddress,
              userAgent,
              status: 'FAILED',
              type: 'LOGIN',
              message: 'Account is not active',
              createdAt: knex.fn.now(),
            })
            .catch(console.error);
          throw new Error('Your account is not active. Please contact support.');
        }

        // direct permissions
        const perms = await knex('Permission')
          .where({ userId: user.id, target: PermissionTarget.USER })
          .leftJoin('Resource', 'Permission.resourceId', 'Resource.id')
          .select('Permission.id as permissionId', 'Resource.slug as resourceSlug');
        const permIds = perms.map((p) => p.permissionId);
        let actRows: { permissionId: string; slug: string }[] = [];
        if (permIds.length) {
          actRows = await knex('PermissionAction')
            .whereIn('permissionId', permIds)
            .leftJoin('Action', 'PermissionAction.actionId', 'Action.id')
            .select('PermissionAction.permissionId', 'Action.slug');
        }
        const directPermissions: Permission[] = perms.map((p) => ({
          target: PermissionTarget.USER,
          resource: { slug: p.resourceSlug },
          actions: actRows
            .filter((a) => a.permissionId === p.permissionId)
            .map((a) => ({ slug: a.slug })),
        }));

        // memberships
        const mems = await knex('OrganizationMember')
          .where({ userId: user.id })
          .leftJoin('Organization', 'OrganizationMember.organizationId', 'Organization.id')
          .leftJoin('Role', 'OrganizationMember.roleId', 'Role.id')
          .select(
            'OrganizationMember.id as membershipId',
            'Organization.id as orgId',
            'Organization.name as orgName',
            'Organization.slug as orgSlug',
            'Role.id as roleId',
            'Role.name as roleName',
            'Role.description as roleDescription'
          );
        const orgIds = mems.map((m) => m.orgId).filter(Boolean);

        let orgPerms: any[] = [];
        if (orgIds.length) {
          orgPerms = await knex('Permission')
            .whereIn('organizationId', orgIds)
            .andWhere('target', PermissionTarget.ORGANIZATION)
            .leftJoin('Resource', 'Permission.resourceId', 'Resource.id')
            .select(
              'Permission.id as permissionId',
              'Permission.organizationId',
              'Resource.slug as resourceSlug'
            );
        }
        const orgPermIds = orgPerms.map((p) => p.permissionId);
        let orgActs: { permissionId: string; slug: string }[] = [];
        if (orgPermIds.length) {
          orgActs = await knex('PermissionAction')
            .whereIn('permissionId', orgPermIds)
            .leftJoin('Action', 'PermissionAction.actionId', 'Action.id')
            .select('PermissionAction.permissionId', 'Action.slug');
        }

        const roleIds = mems.map((m) => m.roleId).filter(Boolean);
        let rolePerms: any[] = [];
        if (roleIds.length) {
          rolePerms = await knex('Permission')
            .whereIn('roleId', roleIds)
            .andWhere('target', PermissionTarget.ROLE)
            .leftJoin('Resource', 'Permission.resourceId', 'Resource.id')
            .select(
              'Permission.id as permissionId',
              'Permission.roleId',
              'Resource.slug as resourceSlug'
            );
        }
        const rolePermIds = rolePerms.map((p) => p.permissionId);
        let roleActs: { permissionId: string; slug: string }[] = [];
        if (rolePermIds.length) {
          roleActs = await knex('PermissionAction')
            .whereIn('permissionId', rolePermIds)
            .leftJoin('Action', 'PermissionAction.actionId', 'Action.id')
            .select('PermissionAction.permissionId', 'Action.slug');
        }

        const memberships = mems.map((m) => ({
          id: m.membershipId,
          role: m.roleId
            ? {
                id: m.roleId,
                name: m.roleName,
                description: m.roleDescription || '',
                permissions: rolePerms
                  .filter((rp) => rp.roleId === m.roleId)
                  .map((rp) => ({
                    target: PermissionTarget.ROLE,
                    resource: { slug: rp.resourceSlug },
                    actions: roleActs
                      .filter((ra) => ra.permissionId === rp.permissionId)
                      .map((ra) => ({ slug: ra.slug })),
                  })),
              }
            : null,
          organization: {
            id: m.orgId,
            name: m.orgName,
            slug: m.orgSlug,
            permissions: orgPerms
              .filter((op) => op.organizationId === m.orgId)
              .map((op) => ({
                target: PermissionTarget.ORGANIZATION,
                resource: { slug: op.resourceSlug },
                actions: orgActs
                  .filter((oa) => oa.permissionId === op.permissionId)
                  .map((oa) => ({ slug: oa.slug })),
              })),
          },
        }));

        // user roles
        const ur = await knex('UserRole')
          .where({ userId: user.id })
          .leftJoin('Role', 'UserRole.roleId', 'Role.id')
          .select('Role.id', 'Role.name', 'Role.description');
        const userRoles = ur.map((r) => ({
          role: { id: r.id, name: r.name, description: r.description || '' },
        }));

        // success log
        await knex('SecurityLog')
          .insert({
            userId: user.id,
            email: user.email,
            ipAddress: ipAddress === '::1' ? '127.0.0.1' : ipAddress,
            userAgent,
            status: 'SUCCESS',
            type: 'LOGIN',
            message: `Successful login for user ${user.email}`,
            createdAt: knex.fn.now(),
          })
          .catch(console.error);

        return { ...user, permissions: directPermissions, memberships, userRoles };
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user, trigger }) {
      if (trigger === 'signIn' && user) {
        Object.assign(token, user);
      }
      return token;
    },
    async session({ session, token }) {
      session.user = { ...session.user, ...token };
      return session;
    },
  },
};
