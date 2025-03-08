import { PrismaAdapter } from '@next-auth/prisma-adapter';
import { NextAuthOptions } from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import { prisma } from '@/lib/prisma';
import bcrypt from 'bcryptjs';
import { UserStatus, PermissionTarget } from '@prisma/client';
import { Permission } from './types';

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma),
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
            await prisma.securityLog.create({
              data: {
                email: credentials?.email || '',
                ipAddress: ipAddress === '::1' ? '127.0.0.1' : ipAddress,
                userAgent: userAgent,
                status: 'FAILED',
                type: 'LOGIN',
                message: 'Missing credentials',
              },
            });
          } catch (error) {
            console.error('Failed to create security log:', error);
          }
          throw new Error('Please provide both email and password');
        }

        const user = await prisma.user.findUnique({
          where: { email: credentials.email.toLowerCase() },
          include: {
            permissions: {
              include: {
                resource: true,
                actions: {
                  include: {
                    action: true,
                  },
                },
              },
            },
            userRoles: {
              include: {
                role: true,
              },
            },
            memberships: {
              include: {
                organization: {
                  include: {
                    permissions: {
                      include: {
                        resource: true,
                        actions: {
                          include: {
                            action: true,
                          },
                        },
                      },
                    },
                  },
                },
                role: {
                  include: {
                    permissions: {
                      include: {
                        resource: true,
                        actions: {
                          include: {
                            action: true,
                          },
                        },
                      },
                    },
                  },
                },
              },
              where: {
                organization: {
                  parentId: null,
                },
              },
            },
          },
        });

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
