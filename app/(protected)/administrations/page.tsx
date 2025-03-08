'use client';

import { useSession } from 'next-auth/react';
import { Card, Typography, Button, Avatar } from 'antd';
import {
  TeamOutlined,
  UserOutlined,
  ApartmentOutlined,
  SafetyCertificateOutlined,
  LockOutlined,
} from '@ant-design/icons';
import Link from 'next/link';
import { redirect } from 'next/navigation';
import { usePermission } from '@/lib/auth/permissions';

const { Title, Text } = Typography;

const CARD_STYLES = {
  height: '100%',
  display: 'flex',
  flexDirection: 'column' as const,
};

const CARD_BODY_STYLES = {
  flex: 1,
  display: 'flex',
  flexDirection: 'column' as const,
};

export default function AdministrationsPage() {
  const { data: session } = useSession();
  const canViewUsers = usePermission('user', 'view');
  const canViewOrganizations = usePermission('organization', 'view');
  const canViewRoles = usePermission('role', 'view');
  const canViewPermissions = usePermission('permission', 'view');
  const canViewSecurityLogs = usePermission('security-log', 'view');

  if (!session?.user) {
    redirect('/auth/login');
  }

  const isAdmin = session.user.userRoles?.some(ur => ur.role.name === 'ADMIN');

  return (
    <div className="p-8 max-w-7xl mx-auto">
      <div className="mb-8">
        <Title level={2}>
          Welcome back, {session.user.firstName + ' ' + session.user.lastName || session.user.email}
          !
        </Title>
        <Text type="secondary">Manage your organizations and workspace</Text>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-1 lg:grid-cols-2 gap-6">
        {/* User Profile Card */}
        <Card style={CARD_STYLES} styles={{ body: CARD_BODY_STYLES }}>
          <div className="flex flex-col h-full">
            <div className="flex items-start space-x-4 mb-auto">
              <Avatar
                size={64}
                icon={<UserOutlined />}
                src={session.user.avatar}
                className="flex-shrink-0"
              />
              <div className="flex-grow">
                <Title level={4} className="!mb-2">
                  {session.user.firstName} {session.user.lastName}
                </Title>
                <Text type="secondary" className="block mb-1">
                  {session.user.email}
                </Text>
                <Text type="secondary" className="block">
                  Roles: {session.user.userRoles?.map(ur => ur.role.name).join(', ') || 'No Role'}
                </Text>
                <div className="flex flex-col space-y-2 mt-4">
                  <Text strong className="block">
                    Profile
                  </Text>
                  <Text type="secondary">View and edit your profile</Text>
                </div>
              </div>
            </div>
            <div className="mt-4 pt-4 border-t">
              <Link href="/administrations/users/profile/edit">
                <Button block>Edit Profile</Button>
              </Link>
            </div>
          </div>
        </Card>

        {/* Users Management Card */}
        {canViewUsers && (
          <Card style={CARD_STYLES} styles={{ body: CARD_BODY_STYLES }}>
            <div className="flex flex-col h-full">
              <Title level={4} className="flex items-center !mb-4">
                <TeamOutlined className="mr-2" /> Users Management
              </Title>
              <div className="flex-grow">
                <Text type="secondary" className="block mb-4">
                  Manage users in your organization. Add new users, update their information, or
                  remove existing users.
                </Text>
                <div className="flex flex-col space-y-2">
                  <Text strong className="block">
                    Users
                  </Text>
                  <Text type="secondary">View and manage organization members</Text>
                </div>
              </div>
              <div className="mt-4 pt-4 border-t">
                <Link href="/administrations/users">
                  <Button type="primary" icon={<TeamOutlined />} block>
                    Manage Users
                  </Button>
                </Link>
              </div>
            </div>
          </Card>
        )}

        {/* Organizations Management Card */}
        {canViewOrganizations && (
          <Card style={CARD_STYLES} styles={{ body: CARD_BODY_STYLES }}>
            <div className="flex flex-col h-full">
              <Title level={4} className="flex items-center !mb-4">
                <ApartmentOutlined className="mr-2" /> Organizations Management
              </Title>
              <div className="flex-grow">
                <Text type="secondary" className="block mb-4">
                  Manage organizations and their structures. Create new organizations, update their
                  information, and manage organization hierarchies.
                </Text>
                <div className="flex flex-col space-y-2">
                  <Text strong className="block">
                    Organizations
                  </Text>
                  <Text type="secondary">
                    {isAdmin
                      ? 'Create and manage organizations across the system'
                      : 'View and manage your organizations'}
                  </Text>
                </div>
              </div>
              <div className="mt-4 pt-4 border-t">
                <Link href="/administrations/organizations">
                  <Button type="primary" icon={<ApartmentOutlined />} block>
                    Manage Organizations
                  </Button>
                </Link>
              </div>
            </div>
          </Card>
        )}

        {/* Roles Management Card */}
        {canViewRoles && (
          <Card style={CARD_STYLES} styles={{ body: CARD_BODY_STYLES }}>
            <div className="flex flex-col h-full">
              <Title level={4} className="flex items-center !mb-4">
                <SafetyCertificateOutlined className="mr-2" /> Roles Management
              </Title>
              <div className="flex-grow">
                <Text type="secondary" className="block mb-4">
                  Manage roles and permissions. Create new roles, assign permissions, and manage
                  role assignments.
                </Text>
                <div className="flex flex-col space-y-2">
                  <Text strong className="block">
                    Roles
                  </Text>
                  <Text type="secondary">
                    {isAdmin
                      ? 'Create and manage roles across all organizations'
                      : 'View and manage roles in your organizations'}
                  </Text>
                </div>
              </div>
              <div className="mt-4 pt-4 border-t">
                <Link href="/administrations/roles">
                  <Button type="primary" icon={<SafetyCertificateOutlined />} block>
                    Manage Roles
                  </Button>
                </Link>
              </div>
            </div>
          </Card>
        )}

        {/* Security Logs Card */}
        {canViewSecurityLogs && (
          <Card style={CARD_STYLES} styles={{ body: CARD_BODY_STYLES }}>
            <div className="flex flex-col h-full">
              <Title level={4} className="flex items-center !mb-4">
                <SafetyCertificateOutlined className="mr-2" /> Security Logs
              </Title>
              <div className="flex-grow">
                <Text type="secondary" className="block mb-4">
                  Monitor and track all authentication attempts and security-related events in the
                  system.
                </Text>
                <div className="flex flex-col space-y-2">
                  <Text strong className="block">
                    Authentication Logs
                  </Text>
                  <Text type="secondary">
                    View successful and failed login attempts, IP addresses, and user agents
                  </Text>
                </div>
              </div>
              <div className="mt-4 pt-4 border-t">
                <Link href="/administrations/security-logs">
                  <Button type="primary" icon={<SafetyCertificateOutlined />} block>
                    View Security Logs
                  </Button>
                </Link>
              </div>
            </div>
          </Card>
        )}

        {/* Permissions Management Card */}
        {canViewPermissions && (
          <Card style={CARD_STYLES} styles={{ body: CARD_BODY_STYLES }}>
            <div className="flex flex-col h-full">
              <Title level={4} className="flex items-center !mb-4">
                <LockOutlined className="mr-2" /> Permissions Management
              </Title>
              <div className="flex-grow">
                <Text type="secondary" className="block mb-4">
                  Manage permissions and access control. Create new permissions, update existing
                  ones, and manage resource access.
                </Text>
                <div className="flex flex-col space-y-2">
                  <Text strong className="block">
                    Permissions
                  </Text>
                  <Text type="secondary">
                    {isAdmin
                      ? 'Create and manage permissions across all resources'
                      : 'View and manage resource permissions'}
                  </Text>
                </div>
              </div>
              <div className="mt-4 pt-4 border-t">
                <Link href="/administrations/permissions">
                  <Button type="primary" icon={<LockOutlined />} block>
                    Manage Permissions
                  </Button>
                </Link>
              </div>
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}
