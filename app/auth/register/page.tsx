'use client';

import { Card, Typography } from 'antd';
import RegisterForm from './register-form';

const { Title, Text } = Typography;

export default function RegisterPage() {
  return (
    <div className="min-h-screen w-full flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <Card className="w-full max-w-md shadow-md">
        <div className="text-center mb-8">
          <Title level={2}>Create your account</Title>
          <Text type="secondary">Fill in your information to create an account</Text>
        </div>
        <RegisterForm />
      </Card>
    </div>
  );
}
