'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Form, Input, Button } from 'antd';
import { UserOutlined, LockOutlined, PhoneOutlined, MailOutlined } from '@ant-design/icons';
import { signIn } from 'next-auth/react';
import { postRequest } from '@/lib/apiClient';
import { useNotification } from '@/contexts/NotificationContext';

type FormValues = {
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
  phone?: string;
};

export default function RegisterForm() {
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const [form] = Form.useForm();
  const { showNotification } = useNotification();

  const onFinish = async (values: FormValues) => {
    setLoading(true);
    try {
      await postRequest('/api/auth/register', values);

      showNotification('success', 'Success', 'Account created successfully');

      // Auto login after successful registration
      const result = await signIn('credentials', {
        email: values.email,
        password: values.password,
        redirect: false,
      });

      if (result?.error) {
        showNotification('error', 'Login Failed', 'Account created but automatic login failed');
        return;
      }

      router.push('/');
    } catch (error) {
      showNotification(
        'error',
        'Registration Failed',
        error instanceof Error ? error.message : 'Failed to create account'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <Form form={form} name="register" onFinish={onFinish} layout="vertical" requiredMark={false}>
      <div className="grid grid-cols-2 gap-4">
        <Form.Item name="firstName" label="First Name">
          <Input prefix={<UserOutlined />} placeholder="First Name" />
        </Form.Item>

        <Form.Item name="lastName" label="Last Name">
          <Input prefix={<UserOutlined />} placeholder="Last Name" />
        </Form.Item>
      </div>

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
        rules={[
          { required: true, message: 'Please input your password!' },
          { min: 8, message: 'Password must be at least 8 characters!' },
        ]}
      >
        <Input.Password prefix={<LockOutlined />} placeholder="Password" />
      </Form.Item>

      <Form.Item name="phone" label="Phone Number">
        <Input prefix={<PhoneOutlined />} placeholder="Phone Number" />
      </Form.Item>

      <Form.Item>
        <Button type="primary" htmlType="submit" loading={loading} block>
          Create Account
        </Button>
      </Form.Item>

      <div className="text-center">
        <Link href="/auth/login" className="text-blue-600 hover:text-blue-700">
          Already have an account? Sign in
        </Link>
      </div>
    </Form>
  );
}
