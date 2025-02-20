'use client';

import { Card, Typography } from 'antd';
import LoginForm from './login-form';

const { Title, Text } = Typography;

export default function LoginPage() {
  return (
    <div className="min-h-screen w-full flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <Card className="w-full max-w-md shadow-md">
        <div className="text-center mb-8">
          <Title level={2}>Welcome back</Title>
          <Text type="secondary">Sign in to your account</Text>
        </div>
        <LoginForm />
      </Card>
    </div>
  );
}
