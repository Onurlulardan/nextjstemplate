'use client';

import { useSession, SessionProvider } from 'next-auth/react';
import { Layout, theme } from 'antd';
import Navbar from '@/core/layout/components/Navbar';
import Sidebar from '@/core/layout/components/Sidebar';
import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

const { Content } = Layout;

function ProtectedContent({ children }: { children: React.ReactNode }) {
  const { data: session, status } = useSession();
  const [collapsed, setCollapsed] = useState(false);
  const { token } = theme.useToken();
  const router = useRouter();

  useEffect(() => {
    if (status === 'unauthenticated') {
      router.push('/auth/login');
    }
  }, [status, router]);

  if (status === 'loading' || !session) {
    return null;
  }

  return (
    <Layout style={{ minHeight: '100vh', padding: 20 }}>
      <Sidebar collapsed={collapsed} />
      <Layout>
        <Navbar collapsed={collapsed} setCollapsed={setCollapsed} />
        <Content
          style={{
            margin: '24px 16px 0px 16px',
            padding: 24,
            background: token.colorBgContainer,
            borderRadius: '8px',
          }}
        >
          {children}
        </Content>
      </Layout>
    </Layout>
  );
}

export default function ProtectedLayout({ children }: { children: React.ReactNode }) {
  return (
    <SessionProvider>
      <ProtectedContent>{children}</ProtectedContent>
    </SessionProvider>
  );
}
