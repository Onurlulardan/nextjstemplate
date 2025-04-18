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
  pages: { signIn: '/auth/login', newUser: '/auth/register', error: '/auth/error' },
  providers: [
    CredentialsProvider({
      name: 'Credentials',
      credentials: {
        email: { label: 'Email', type: 'text' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials, request) {
        // IP and User-Agent
        const ipAddress = request?.headers['x-forwarded-for']?.split(',')[0] || '0.0.0.0';
        const userAgent = request?.headers['user-agent'] || 'Unknown';

        // Validate input
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

        // Fetch user
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

        // Verify password
        const validPassword = await bcrypt.compare(credentials.password, user.password);
        if (!validPassword) {
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

        // Check user status
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

        // Direct permissions
        const permissionsRaw = await knex('Permission')
          .where({ userId: user.id, target: PermissionTarget.USER })
          .leftJoin('Resource', 'Permission.resourceId', 'Resource.id')
          .select('Permission.id as permissionId', 'Resource.slug as resourceSlug');
        const permissionIds = permissionsRaw.map((p) => p.permissionId);
        let actionsRaw: { permissionId: string; slug: string }[] = [];
        if (permissionIds.length) {
          actionsRaw = await knex('PermissionAction')
            .whereIn('permissionId', permissionIds)
            .leftJoin('Action', 'PermissionAction.actionId', 'Action.id')
            .select('PermissionAction.permissionId', 'Action.slug');
        }
        const directPermissions: Permission[] = permissionsRaw.map((p) => ({
          target: PermissionTarget.USER,
          resource: { slug: p.resourceSlug },
          actions: actionsRaw
            .filter((a) => a.permissionId === p.permissionId)
            .map((a) => ({ slug: a.slug })),
        }));

        // Memberships & organization/role permissions
        const membershipsRaw = await knex('OrganizationMember')
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

        const orgIds = membershipsRaw.map((m) => m.orgId).filter(Boolean);
        let orgPermissionsRaw: any[] = [];
        if (orgIds.length) {
          orgPermissionsRaw = await knex('Permission')
            .whereIn('organizationId', orgIds)
            .andWhere('target', PermissionTarget.ORGANIZATION)
            .leftJoin('Resource', 'Permission.resourceId', 'Resource.id')
            .select(
              'Permission.id as permissionId',
              'Permission.organizationId',
              'Resource.slug as resourceSlug'
            );
        }
        const orgPermissionIds = orgPermissionsRaw.map((p) => p.permissionId);
        let orgActionsRaw: { permissionId: string; slug: string }[] = [];
        if (orgPermissionIds.length) {
          orgActionsRaw = await knex('PermissionAction')
            .whereIn('permissionId', orgPermissionIds)
            .leftJoin('Action', 'PermissionAction.actionId', 'Action.id')
            .select('PermissionAction.permissionId', 'Action.slug');
        }

        const roleIds = membershipsRaw.map((m) => m.roleId).filter(Boolean);
        let rolePermissionsRaw: any[] = [];
        if (roleIds.length) {
          rolePermissionsRaw = await knex('Permission')
            .whereIn('roleId', roleIds)
            .andWhere('target', PermissionTarget.ROLE)
            .leftJoin('Resource', 'Permission.resourceId', 'Resource.id')
            .select(
              'Permission.id as permissionId',
              'Permission.roleId',
              'Resource.slug as resourceSlug'
            );
        }
        const rolePermissionIds = rolePermissionsRaw.map((p) => p.permissionId);
        let roleActionsRaw: { permissionId: string; slug: string }[] = [];
        if (rolePermissionIds.length) {
          roleActionsRaw = await knex('PermissionAction')
            .whereIn('permissionId', rolePermissionIds)
            .leftJoin('Action', 'PermissionAction.actionId', 'Action.id')
            .select('PermissionAction.permissionId', 'Action.slug');
        }

        const memberships = membershipsRaw.map((m) => ({
          id: m.membershipId,
          role: m.roleId
            ? {
                id: m.roleId,
                name: m.roleName,
                description: m.roleDescription || '',
                permissions: rolePermissionsRaw
                  .filter((p) => p.roleId === m.roleId)
                  .map((p) => ({
                    target: PermissionTarget.ROLE,
                    resource: { slug: p.resourceSlug },
                    actions: roleActionsRaw
                      .filter((a) => a.permissionId === p.permissionId)
                      .map((a) => ({ slug: a.slug })),
                  })),
              }
            : null,
          organization: {
            id: m.orgId,
            name: m.orgName,
            slug: m.orgSlug,
            permissions: orgPermissionsRaw
              .filter((p) => p.organizationId === m.orgId)
              .map((p) => ({
                target: PermissionTarget.ORGANIZATION,
                resource: { slug: p.resourceSlug },
                actions: orgActionsRaw
                  .filter((a) => a.permissionId === p.permissionId)
                  .map((a) => ({ slug: a.slug })),
              })),
          },
        }));

        // User roles
        const userRolesRaw = await knex('UserRole')
          .where({ userId: user.id })
          .leftJoin('Role', 'UserRole.roleId', 'Role.id')
          .select('Role.id', 'Role.name', 'Role.description');
        const userRoles = userRolesRaw.map((ur) => ({
          role: { id: ur.id, name: ur.name, description: ur.description || '' },
        }));

        // Log successful login
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
        Object.assign(token, {
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          phone: user.phone,
          avatar: user.avatar,
          status: user.status,
          permissions: user.permissions,
          memberships: user.memberships,
          userRoles: user.userRoles,
        });
      }
      return token;
    },
    async session({ session, token }) {
      Object.assign(session.user, {
        id: token.id,
        firstName: token.firstName,
        lastName: token.lastName,
        phone: token.phone,
        avatar: token.avatar,
        status: token.status,
        permissions: token.permissions,
        memberships: token.memberships,
        userRoles: token.userRoles,
      });
      return session;
    },
  },
};
