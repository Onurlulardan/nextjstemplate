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
