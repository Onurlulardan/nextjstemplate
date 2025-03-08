'use client';

import { useState, useEffect } from 'react';
import { Card, Row, Col, Statistic, Typography, Button } from 'antd';
import { useSession } from 'next-auth/react';
import { usePermission } from '@/lib/auth/permissions';
import Link from 'next/link';
import { ArrowRightOutlined } from '@ant-design/icons';
import { getRequest } from '@/lib/apiClient';

const { Title, Text } = Typography;

interface DashboardStats {
  totalOrganizations: number;
  totalUsers: number;
  activeUsers: number;
}

export default function Dashboard() {
  const { data: session } = useSession();
  const [stats, setStats] = useState<DashboardStats>({
    totalOrganizations: 0,
    totalUsers: 0,
    activeUsers: 0,
  });

  // Permission hooks
  const canViewStats = usePermission('dashboard', 'view');

  const fetchDashboardData = async () => {
    if (canViewStats) {
      try {
        const data = await getRequest<DashboardStats>('/dashboard/stats');
        setStats(data);
      } catch (error) {
        console.error('Failed to fetch dashboard stats:', error);
      }
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, [canViewStats]);

  return (
    <div className="flex items-center justify-center p-4 h-full">
      <Card className="w-full text-center">
        <Title level={2}>Welcome to NextJS Starter Template</Title>
        <Text className="block mb-8 text-lg">A modern and scalable system for your business</Text>

        {session ? (
          <div>
            <Link href="/administrations">
              <Button type="primary" size="large" icon={<ArrowRightOutlined />}>
                Go to Administrations
              </Button>
            </Link>

            {canViewStats && (
              <Row gutter={16} className="mb-8 mt-8">
                <Col span={8}>
                  <Card>
                    <Statistic title="Total Organizations" value={stats.totalOrganizations} />
                  </Card>
                </Col>
                <Col span={8}>
                  <Card>
                    <Statistic title="Total Users" value={stats.totalUsers} />
                  </Card>
                </Col>
                <Col span={8}>
                  <Card>
                    <Statistic title="Active Users" value={stats.activeUsers} />
                  </Card>
                </Col>
              </Row>
            )}
          </div>
        ) : (
          <Link href="/auth/signin">
            <Button type="primary" size="large" icon={<ArrowRightOutlined />}>
              Sign In
            </Button>
          </Link>
        )}
      </Card>
    </div>
  );
}
