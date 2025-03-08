'use client';

import { useEffect, useState } from 'react';
import { Card, Typography, Table } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { getRequest } from '@/lib/apiClient';
import { usePermission } from '@/lib/auth/permissions';

const { Title } = Typography;

interface SecurityLog {
  id: string;
  email: string;
  ipAddress: string;
  userAgent: string;
  status: string;
  type: string;
  message: string;
  createdAt: string;
  user?: {
    firstName: string;
    lastName: string;
  };
}

export default function SecurityLogsPage() {
  const [logs, setLogs] = useState<SecurityLog[]>([]);
  const [loading, setLoading] = useState(true);
  const canViewLogs = usePermission('security_log', 'view');

  useEffect(() => {
    if (canViewLogs) {
      fetchLogs();
    }
  }, [canViewLogs]);

  const fetchLogs = async () => {
    try {
      const data = await getRequest<SecurityLog[]>('/administrations/security-logs');
      setLogs(data);
    } catch (error) {
      console.error('Failed to fetch security logs:', error);
    } finally {
      setLoading(false);
    }
  };

  const columns: ColumnsType<SecurityLog> = [
    {
      title: 'Date',
      dataIndex: 'createdAt',
      key: 'createdAt',
      render: (date: string) => new Date(date).toLocaleString(),
      width: 180,
    },
    {
      title: 'Type',
      dataIndex: 'type',
      key: 'type',
      width: 120,
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (status: string) => (
        <span style={{ color: status === 'SUCCESS' ? '#52c41a' : '#ff4d4f' }}>{status}</span>
      ),
    },
    {
      title: 'Email',
      dataIndex: 'email',
      key: 'email',
      width: 200,
    },
    {
      title: 'User',
      key: 'user',
      width: 150,
      render: (record: SecurityLog) =>
        record.user ? `${record.user.firstName} ${record.user.lastName}` : '-',
    },
    {
      title: 'IP Address',
      dataIndex: 'ipAddress',
      key: 'ipAddress',
      width: 130,
    },
    {
      title: 'Browser',
      dataIndex: 'userAgent',
      key: 'userAgent',
      ellipsis: true,
    },
    {
      title: 'Message',
      dataIndex: 'message',
      key: 'message',
      ellipsis: true,
    },
  ];

  if (!canViewLogs) {
    return null;
  }

  return (
    <Card>
      <Title level={2}>Security Logs</Title>
      <Table
        columns={columns}
        dataSource={logs}
        loading={loading}
        rowKey="id"
        pagination={{
          defaultPageSize: 20,
          showSizeChanger: true,
          showTotal: (total) => `Total ${total} records`,
        }}
      />
    </Card>
  );
}
