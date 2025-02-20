'use client';

import { Form, Input, Select, Button } from 'antd';
import { User, UserRole, UserStatus } from '@prisma/client';
import { useEffect } from 'react';

type UserFormData = Omit<User, 'id' | 'createdAt' | 'updatedAt' | 'emailVerified' | 'avatar'>;

interface UserFormProps {
  initialValues?: Partial<UserFormData>;
  onSubmit: (values: UserFormData) => Promise<void>;
  loading: boolean;
}

export function UserForm({ initialValues, onSubmit, loading }: UserFormProps) {
  const [form] = Form.useForm();

  useEffect(() => {
    form.resetFields();
    if (initialValues) {
      form.setFieldsValue(initialValues);
    }
  }, [form, initialValues]);

  return (
    <Form
      form={form}
      layout="vertical"
      onFinish={onSubmit}
      initialValues={{
        role: UserRole.USER,
        status: UserStatus.ACTIVE,
        ...initialValues,
      }}
    >
      <Form.Item
        label="Email"
        name="email"
        rules={[
          { required: true, message: 'Please input email' },
          { type: 'email', message: 'Please enter a valid email' },
        ]}
      >
        <Input />
      </Form.Item>

      {!initialValues && (
        <Form.Item
          label="Password"
          name="password"
          rules={[{ required: true, message: 'Please input password' }]}
        >
          <Input.Password />
        </Form.Item>
      )}

      {initialValues && (
        <Form.Item
          label="New Password"
          name="password"
          extra="Leave blank to keep current password"
        >
          <Input.Password />
        </Form.Item>
      )}

      <Form.Item label="First Name" name="firstName">
        <Input />
      </Form.Item>

      <Form.Item label="Last Name" name="lastName">
        <Input />
      </Form.Item>

      <Form.Item label="Phone" name="phone">
        <Input />
      </Form.Item>

      <Form.Item label="Role" name="role">
        <Select>
          <Select.Option value={UserRole.ADMIN}>Admin</Select.Option>
          <Select.Option value={UserRole.USER}>User</Select.Option>
        </Select>
      </Form.Item>

      <Form.Item label="Status" name="status">
        <Select>
          <Select.Option value={UserStatus.ACTIVE}>Active</Select.Option>
          <Select.Option value={UserStatus.INACTIVE}>Inactive</Select.Option>
          <Select.Option value={UserStatus.SUSPENDED}>Suspended</Select.Option>
        </Select>
      </Form.Item>

      <Form.Item>
        <Button type="primary" htmlType="submit" loading={loading} block>
          {initialValues ? 'Update User' : 'Create User'}
        </Button>
      </Form.Item>
    </Form>
  );
}
