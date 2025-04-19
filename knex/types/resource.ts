export interface Resource {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  createdAt: Date;
  updatedAt: Date;
  
  // İlişkili alanlar için opsiyonel alanlar
  permissions?: any[];
  _count?: {
    permissions?: number;
  };
}
