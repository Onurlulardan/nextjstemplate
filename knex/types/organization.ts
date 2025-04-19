import { OrgStatus } from './enums';

export interface Organization {
  id: string;
  name: string;
  status: OrgStatus;
  ownerId: string;
  parentId?: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface OrganizationMember {
  id: string;
  organizationId: string;
  userId: string;
  roleId?: string | null;
  createdAt: Date;
  updatedAt: Date;
}
