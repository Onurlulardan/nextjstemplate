import { NextAuthKnexAdapter } from '@/knex/adapters/nextauth-knex-adapter';
import knex from '@/knex';
import { NextAuthOptions } from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import bcrypt from 'bcryptjs';
import { UserStatus, PermissionTarget } from './types';
import { Permission } from './types';

export const authOptions: NextAuthOptions = {
  adapter: NextAuthKnexAdapter(knex),
  session: {
    strategy: 'jwt',
    maxAge: Number(process.env.NEXTAUTH_SESSION_MAX_AGE) || 7 * 24 * 60 * 60, // 7 days fallback
    updateAge: Number(process.env.NEXTAUTH_SESSION_UPDATE_AGE) || 60 * 60, // 1 hour fallback
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
      async authorize(credentials, request) {
        // Get IP and user agent from request headers
        const ipAddress = request?.headers?.['x-forwarded-for']?.split(',')[0] || '0.0.0.0';
        const userAgent = request?.headers?.['user-agent'] || 'Unknown';

        if (!credentials?.email || !credentials?.password) {
          try {
            await knex('SecurityLog').insert({
              email: credentials?.email || '',
              ipAddress: ipAddress === '::1' ? '127.0.0.1' : ipAddress,
              userAgent: userAgent,
              status: 'FAILED',
              type: 'LOGIN',
              message: 'Missing credentials',
              createdAt: knex.fn.now(),
            });
          } catch (error) {
            console.error('Failed to create security log:', error);
          }
          throw new Error('Please provide both email and password');
        }

        // User + all relations fetch (manual join)
        const user = await knex('User')
          .whereRaw('LOWER(email) = ?', [credentials.email.toLowerCase()])
          .first();

        if (!user) {
          try {
            await knex('SecurityLog').insert({
              email: credentials.email.toLowerCase(),
              ipAddress: ipAddress === '::1' ? '127.0.0.1' : ipAddress,
              userAgent: userAgent,
              status: 'FAILED',
              type: 'LOGIN',
              message: 'Invalid credentials',
              createdAt: knex.fn.now(),
            });
          } catch (error) {
            console.error('Failed to create security log:', error);
          }
          throw new Error('Invalid email or password');
        }

        if (!(await bcrypt.compare(credentials.password, user.password))) {
          try {
            await knex('SecurityLog').insert({
              email: credentials.email.toLowerCase(),
              ipAddress: ipAddress === '::1' ? '127.0.0.1' : ipAddress,
              userAgent: userAgent,
              status: 'FAILED',
              type: 'LOGIN',
              message: 'Invalid credentials',
              createdAt: knex.fn.now(),
            });
          } catch (error) {
            console.error('Failed to create security log:', error);
          }
          throw new Error('Invalid email or password');
        }

        if (user.status !== UserStatus.ACTIVE) {
          try {
            await knex('SecurityLog').insert({
              userId: user.id,
              email: user.email,
              ipAddress: ipAddress === '::1' ? '127.0.0.1' : ipAddress,
              userAgent: userAgent,
              status: 'FAILED',
              type: 'LOGIN',
              message: 'Account is not active',
              createdAt: knex.fn.now(),
            });
          } catch (error) {
            console.error('Failed to create security log:', error);
          }
          throw new Error('Your account is not active. Please contact support.');
        }

        // Fetch direct permissions
        const permissionsRaw = await knex('Permission')
          .where({ userId: user.id, target: PermissionTarget.USER })
          .leftJoin('Resource', 'Permission.resourceId', 'Resource.id')
          .select(
            'Permission.id as permissionId',
            'Resource.slug as resourceSlug'
          );

        // Fetch actions for each permission
        const permissionIds = permissionsRaw.map((p) => p.permissionId);
        let actionsRaw: { permissionId: string; slug: string }[] = [];
        if (permissionIds.length > 0) {
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

        // Fetch memberships (organization, role, permissions)
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

        // Fetch organization permissions
        const orgIds = membershipsRaw.map((m) => m.orgId).filter(Boolean);
        let orgPermissionsRaw: any[] = [];
        if (orgIds.length > 0) {
          orgPermissionsRaw = await knex('Permission')
            .whereIn('organizationId', orgIds)
            .andWhere('target', PermissionTarget.ORGANIZATION)
            .leftJoin('Resource', 'Permission.resourceId', 'Resource.id')
            .select(
              'Permission.id as permissionId',
              'Permission.organizationId',
              'Resource.slug as resourceSlug',
              'Permission.target'
            );
        }
        const orgPermissionIds = orgPermissionsRaw.map((p) => p.permissionId);
        let orgActionsRaw: { permissionId: string; slug: string }[] = [];
        if (orgPermissionIds.length > 0) {
          orgActionsRaw = await knex('PermissionAction')
            .whereIn('permissionId', orgPermissionIds)
            .leftJoin('Action', 'PermissionAction.actionId', 'Action.id')
            .select('PermissionAction.permissionId', 'Action.slug');
        }

        // Fetch role permissions
        const roleIds = membershipsRaw.map((m) => m.roleId).filter(Boolean);
        let rolePermissionsRaw: any[] = [];
        if (roleIds.length > 0) {
          rolePermissionsRaw = await knex('Permission')
            .whereIn('roleId', roleIds)
            .andWhere('target', PermissionTarget.ROLE)
            .leftJoin('Resource', 'Permission.resourceId', 'Resource.id')
            .select(
              'Permission.id as permissionId',
              'Permission.roleId',
              'Resource.slug as resourceSlug',
              'Permission.target'
            );
        }
        const rolePermissionIds = rolePermissionsRaw.map((p) => p.permissionId);
        let roleActionsRaw: { permissionId: string; slug: string }[] = [];
        if (rolePermissionIds.length > 0) {
          roleActionsRaw = await knex('PermissionAction')
            .whereIn('permissionId', rolePermissionIds)
            .leftJoin('Action', 'PermissionAction.actionId', 'Action.id')
            .select('PermissionAction.permissionId', 'Action.slug');
        }

        // Build memberships
        const memberships = membershipsRaw
          .filter((m) => m.orgId && !m.parentId)
          .map((m) => ({
            id: m.membershipId,
            role: m.roleId
              ? {
                  id: m.roleId,
                  name: m.roleName,
                  permissions: rolePermissionsRaw
                    .filter((p) => p.roleId === m.roleId)
                    .map((p) => ({
                      target: p.target,
                      resource: { slug: p.resourceSlug },
                      actions: roleActionsRaw
                        .filter((a) => a.permissionId === p.permissionId)
                        .map((a) => ({ slug: a.slug })),
                    })),
                  description: m.roleDescription || '',
                }
              : null,
            organization: {
              id: m.orgId,
              name: m.orgName,
              slug: m.orgSlug,
              permissions: orgPermissionsRaw
                .filter((p) => p.organizationId === m.orgId)
                .map((p) => ({
                  target: p.target,
                  resource: { slug: p.resourceSlug },
                  actions: orgActionsRaw
                    .filter((a) => a.permissionId === p.permissionId)
                    .map((a) => ({ slug: a.slug })),
                })),
            },
          }));

        // Fetch user roles
        const userRolesRaw = await knex('UserRole')
          .where({ userId: user.id })
          .leftJoin('Role', 'UserRole.roleId', 'Role.id')
          .select('Role.id', 'Role.name', 'Role.description');
        const userRoles = userRolesRaw.map((ur) => ({
          role: {
            id: ur.id,
            name: ur.name,
            description: ur.description || '',
          },
        }));

        // Log successful login
        try {
          await knex('SecurityLog').insert({
            userId: user.id,
            email: user.email,
            ipAddress: ipAddress === '::1' ? '127.0.0.1' : ipAddress,
            userAgent: userAgent,
            status: 'SUCCESS',
            type: 'LOGIN',
            message: `Successful login for user ${user.email}`,
            createdAt: knex.fn.now(),
          });
        } catch (error) {
          console.error('Failed to create security log:', error);
        }

        return {
          ...user,
          permissions: directPermissions,
          memberships,
          userRoles,
        };
      }

        if (!user || !(await bcrypt.compare(credentials.password, user.password))) {
          try {
            await prisma.securityLog.create({
              data: {
                email: credentials.email.toLowerCase(),
                ipAddress: ipAddress === '::1' ? '127.0.0.1' : ipAddress,
                userAgent: userAgent,
                status: 'FAILED',
                type: 'LOGIN',
                message: 'Invalid credentials',
              },
            });
          } catch (error) {
            console.error('Failed to create security log:', error);
          }
          throw new Error('Invalid email or password');
        }

        if (user.status !== UserStatus.ACTIVE) {
          try {
            await prisma.securityLog.create({
              data: {
                userId: user.id,
                email: user.email,
                ipAddress: ipAddress === '::1' ? '127.0.0.1' : ipAddress,
                userAgent: userAgent,
                status: 'FAILED',
                type: 'LOGIN',
                message: 'Account is not active',
              },
            });
          } catch (error) {
            console.error('Failed to create security log:', error);
          }
          throw new Error('Your account is not active. Please contact support.');
        }

        // Prepare the user's direct permissions
        const directPermissions: Permission[] = user.permissions.map((p) => ({
          target: PermissionTarget.USER,
          resource: {
            slug: p.resource.slug,
          },
          actions: p.actions.map((pa) => ({
            slug: pa.action.slug,
          })),
        }));

        // Prepare permissions for memberships
        const memberships = user.memberships.map((m) => ({
          id: m.id,
          role: m.role
            ? {
                id: m.role.id,
                name: m.role.name,
                permissions: m.role.permissions.map((p) => ({
                  target: p.target,
                  resource: {
                    slug: p.resource.slug,
                  },
                  actions: p.actions.map((a) => ({
                    slug: a.action.slug,
                  })),
                })),
              }
            : null,
          organization: {
            id: m.organization.id,
            name: m.organization.name,
            slug: m.organization.slug,
            permissions: m.organization.permissions.map((p) => ({
              target: p.target,
              resource: {
                slug: p.resource.slug,
              },
              actions: p.actions.map((a) => ({
                slug: a.action.slug,
              })),
            })),
          },
        }));

        // Log successful login
        try {
          await prisma.securityLog.create({
            data: {
              userId: user.id,
              email: user.email,
              ipAddress: ipAddress === '::1' ? '127.0.0.1' : ipAddress,
              userAgent: userAgent,
              status: 'SUCCESS',
              type: 'LOGIN',
              message: `Successful login for user ${user.email}`,
            },
          });
        } catch (error) {
          console.error('Failed to create security log:', error);
        }

        const userRoles = user.userRoles.map((ur) => ({
          role: {
            id: ur.role.id,
            name: ur.role.name,
            description: ur.role.description || '',
          },
        }));

        return {
          ...user,
          permissions: directPermissions,
          memberships,
          userRoles,
        };
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user, trigger }) {
      if (trigger === 'signIn' && user) {
        token.id = user.id;
        token.firstName = user.firstName;
        token.lastName = user.lastName;
        token.phone = user.phone;
        token.avatar = user.avatar;
        token.status = user.status;
        token.permissions = user.permissions;
        token.memberships = user.memberships;
        token.userRoles = user.userRoles;
      }
      return token;
    },
    async session({ session, token }) {
      session.user.id = token.id;
      session.user.firstName = token.firstName;
      session.user.lastName = token.lastName;
      session.user.phone = token.phone;
      session.user.avatar = token.avatar;
      session.user.status = token.status;
      session.user.permissions = token.permissions;
      session.user.memberships = token.memberships;
      session.user.userRoles = token.userRoles;
      return session;
    },
  },
};
