'use client';

import { Layout, Menu, theme } from 'antd';
import { DashboardOutlined, TeamOutlined, SettingOutlined } from '@ant-design/icons';
import Link from 'next/link';

const { Sider } = Layout;

interface SidebarProps {
  collapsed: boolean;
}

export default function Sidebar({ collapsed }: SidebarProps) {
  const { token } = theme.useToken();

  const menuItems = [
    {
      key: '/dashboard',
      icon: <DashboardOutlined />,
      label: <Link href="/dashboard">Dashboard</Link>,
    },
    {
      key: '/administrations',
      icon: <SettingOutlined />,
      label: <Link href="/administrations">Administrations</Link>,
    },
  ];

  return (
    <Sider
      trigger={null}
      collapsible
      collapsed={collapsed}
      style={{ background: token.colorBgContainer, borderRadius: '8px' }}
    >
      {collapsed === false ? (
        <div style={{ height: 32, margin: 16 }}>
          <h1 style={{ fontSize: '18px', color: token.colorText, textAlign: 'center' }}>
            NextJS Starter
          </h1>
        </div>
      ) : (
        <div style={{ height: 32, margin: 16 }}>
          <h1 style={{ fontSize: '18px', color: token.colorText, textAlign: 'center' }}>NEXT</h1>
        </div>
      )}
      <Menu mode="inline" items={menuItems} style={{ background: token.colorBgContainer }} />
    </Sider>
  );
}
