import { $Enums } from './enums';

export interface Permission {
  id: string;
  resourceId: string;
  target: $Enums.PermissionTarget;
  userId: string | null;
  roleId: string | null;
  organizationId: string | null;
  createdAt: Date;
  updatedAt: Date;
  
  // İlişkili alanlar için opsiyonel alanlar
  resource?: any;
  actions?: any[];
  user?: any;
  role?: any;
  organization?: any;
  _count?: any;
}

export interface PermissionAction {
  id: string;
  permissionId: string;
  actionId: string;
  createdAt: Date;
  updatedAt: Date;
}
