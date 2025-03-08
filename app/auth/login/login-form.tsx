'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { signIn } from 'next-auth/react';
import Link from 'next/link';
import { Form, Input, Button } from 'antd';
import { MailOutlined, LockOutlined } from '@ant-design/icons';
import { useNotification } from '@/contexts/NotificationContext';

type FormValues = {
  email: string;
  password: string;
};

export default function LoginForm() {
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const [form] = Form.useForm();
  const { showNotification } = useNotification();

  const onFinish = async (values: FormValues) => {
    setLoading(true);
    try {
      const result = await signIn('credentials', {
        email: values.email.toLowerCase(),
        password: values.password,
        redirect: false,
      });

      if (result?.error) {
        showNotification('error', 'Login Failed', 'Invalid email or password');
        return;
      }

      showNotification('success', 'Success', 'Login successful');
      router.push('/');
    } catch (error) {
      showNotification(
        'error',
        'Error',
        error instanceof Error ? error.message : 'An error occurred during login'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <Form form={form} name="login" onFinish={onFinish} layout="vertical" requiredMark={false}>
      <Form.Item
        name="email"
        label="Email"
        rules={[
          { required: true, message: 'Please input your email!' },
          { type: 'email', message: 'Please enter a valid email!' },
        ]}
      >
        <Input prefix={<MailOutlined />} placeholder="Email" />
      </Form.Item>

      <Form.Item
        name="password"
        label="Password"
        rules={[{ required: true, message: 'Please input your password!' }]}
      >
        <Input.Password prefix={<LockOutlined />} placeholder="Password" />
      </Form.Item>

      <Form.Item>
        <Button type="primary" htmlType="submit" loading={loading} block>
          Sign In
        </Button>
      </Form.Item>

      <div className="text-center">
        <Link href="/auth/register" className="text-blue-600 hover:text-blue-700">
          Don&apos;t have an account? Sign up
        </Link>
      </div>
    </Form>
  );
}
