export interface Role {
  id: string;
  name: string;
  description?: string | null;
  isDefault: boolean;
  organizationId?: string | null;
  createdAt: Date;
  updatedAt: Date;
}
