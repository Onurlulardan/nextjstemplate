import { UserStatus } from './enums';

export interface User {
  id: string;
  email: string;
  password: string;
  firstName?: string | null;
  lastName?: string | null;
  phone?: string | null;
  avatar?: string | null;
  status: UserStatus;
  emailVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface UserRole {
  id: string;
  userId: string;
  roleId: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface SecurityLog {
  id: string;
  userId?: string | null;
  email: string;
  ipAddress: string;
  userAgent: string;
  status: string;
  type: string;
  message: string;
  createdAt: Date;
}
