'use client';

import { Form, Input, Select, Button } from 'antd';
import { User, UserStatus } from '@prisma/client';
import { useEffect, useState } from 'react';
import { getRequest } from '@/lib/apiClient';

type UserFormData = Omit<User, 'id' | 'createdAt' | 'updatedAt' | 'emailVerified' | 'avatar'> & {
  roleIds?: string[];
};

interface UserRole {
  role: {
    id: string;
    name: string;
    description: string;
  };
}

interface UserWithRoles extends Partial<UserFormData> {
  userRoles?: UserRole[];
}

interface UserFormProps {
  initialValues?: UserWithRoles;
  onSubmit: (values: UserFormData) => Promise<void>;
  loading: boolean;
}

interface Role {
  id: string;
  name: string;
  description: string;
  isDefault: boolean;
}

export function UserForm({ initialValues, onSubmit, loading }: UserFormProps) {
  const [form] = Form.useForm();
  const [roles, setRoles] = useState<Role[]>([]);
  const [loadingRoles, setLoadingRoles] = useState(false);

  useEffect(() => {
    form.resetFields();
    if (initialValues) {
      if (initialValues.userRoles) {
        const roleIds = initialValues.userRoles.map((ur: any) => ur.role.id);
        form.setFieldsValue({
          ...initialValues,
          roleIds,
        });
      } else {
        form.setFieldsValue(initialValues);
      }
    }
  }, [form, initialValues]);

  useEffect(() => {
    const fetchRoles = async () => {
      setLoadingRoles(true);
      try {
        const data = await getRequest<Role[]>('/administrations/roles');
        setRoles(data);
        
        if (!initialValues) {
          const defaultRole = data.find(role => role.isDefault);
          if (defaultRole) {
            form.setFieldsValue({
              roleIds: [defaultRole.id]
            });
          }
        }
      } catch (error) {
        console.error('Error fetching roles:', error);
      } finally {
        setLoadingRoles(false);
      }
    };

    fetchRoles();
  }, [form, initialValues]);

  return (
    <Form
      form={form}
      layout="vertical"
      onFinish={onSubmit}
      initialValues={{
        roleIds: [],
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

      <Form.Item label="Roles" name="roleIds">
        <Select 
          mode="multiple"
          placeholder="Select roles"
          loading={loadingRoles}
          optionFilterProp="children"
        >
          {roles.map((role) => (
            <Select.Option key={role.id} value={role.id}>
              {role.name}
            </Select.Option>
          ))}
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
