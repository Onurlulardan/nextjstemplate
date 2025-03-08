import { UserRole, UserStatus, PermissionTarget } from '@prisma/client';
import 'next-auth';

export interface Permission {
  target: PermissionTarget;
  resource: {
    slug: string;
  };
  actions: {
    slug: string;
  }[];
}

export interface UserRoleWithDetails {
  role: {
    id: string;
    name: string;
    description: string;
  };
}

export interface OrganizationRole {
  id: string;
  name: string;
  permissions: Permission[];
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  permissions: Permission[];
}

export interface OrganizationMembership {
  id: string;
  role: OrganizationRole | null;
  organization: Organization;
}

declare module 'next-auth' {
  interface Session {
    user: {
      id: string;
      email: string;
      avatar: string | null;
      firstName: string | null;
      lastName: string | null;
      phone: string | null;
      userRoles: UserRoleWithDetails[];
      status: UserStatus;
      permissions: Permission[];
      memberships: OrganizationMembership[];
    };
  }

  interface User {
    id: string;
    email: string;
    firstName: string | null;
    lastName: string | null;
    phone: string | null;
    avatar: string | null;
    userRoles: UserRoleWithDetails[];
    status: UserStatus;
    permissions: Permission[];
    memberships: OrganizationMembership[];
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    id: string;
    email: string;
    firstName: string | null;
    lastName: string | null;
    phone: string | null;
    avatar: string | null;
    userRoles: UserRoleWithDetails[];
    status: UserStatus;
    permissions: Permission[];
    memberships: OrganizationMembership[];
  }
}
