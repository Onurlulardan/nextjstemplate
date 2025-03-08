'use client';

import { useEffect, useState } from 'react';
import { Form, Input, Button, Select, Switch, Divider, Space } from 'antd';
import { Role, Organization } from '@prisma/client';
import { useSession } from 'next-auth/react';
import { getRequest } from '@/lib/apiClient';

interface RoleFormProps {
  initialValues?: Role | null;
  onSubmit: (values: any) => Promise<void>;
  loading?: boolean;
}

export function RoleForm({ initialValues, onSubmit, loading }: RoleFormProps) {
  const [form] = Form.useForm();
  const { data: session } = useSession();
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [loadingOrgs, setLoadingOrgs] = useState(false);

  useEffect(() => {
    form.resetFields();
    if (initialValues) {
      form.setFieldsValue({
        name: initialValues.name,
        description: initialValues.description,
        isDefault: initialValues.isDefault,
        organizationId: initialValues.organizationId,
      });
    }
  }, [form, initialValues]);

  useEffect(() => {
    fetchOrganizations();
  }, []);

  const fetchOrganizations = async () => {
    setLoadingOrgs(true);
    try {
      const data = await getRequest<Organization[]>('/administrations/organizations');
      setOrganizations(data);
    } catch (error) {
      console.error(error);
    } finally {
      setLoadingOrgs(false);
    }
  };

  const handleSubmit = async (values: any) => {
    try {
      await onSubmit(values);
      form.resetFields();
    } catch (error) {
      console.error(error);
    }
  };

  return (
    <Form
      form={form}
      layout="vertical"
      onFinish={handleSubmit}
      initialValues={{
        isDefault: false,
      }}
    >
      <Form.Item
        name="name"
        label="Role Name"
        rules={[
          { required: true, message: 'Please enter role name' },
          { min: 3, message: 'Role name must be at least 3 characters' },
        ]}
      >
        <Input placeholder="Enter role name" />
      </Form.Item>

      <Form.Item
        name="description"
        label="Description"
        rules={[{ max: 500, message: 'Description cannot be longer than 500 characters' }]}
      >
        <Input.TextArea placeholder="Enter role description" rows={4} showCount maxLength={500} />
      </Form.Item>

      <Form.Item
        name="organizationId"
        label="Organization"
        help="Leave empty to create a global role"
      >
        <Select
          placeholder="Select organization"
          allowClear
          loading={loadingOrgs}
          options={organizations.map((org) => ({
            label: org.name,
            value: org.id,
          }))}
        />
      </Form.Item>

      <Form.Item
        name="isDefault"
        label="Default Role"
        valuePropName="checked"
        help="Default roles are automatically assigned to new members"
      >
        <Switch />
      </Form.Item>

      <Divider />

      <Form.Item className="mb-0">
        <Space className="w-full justify-end">
          <Button onClick={() => form.resetFields()}>Reset</Button>
          <Button type="primary" htmlType="submit" loading={loading}>
            {initialValues ? 'Update' : 'Create'} Role
          </Button>
        </Space>
      </Form.Item>
    </Form>
  );
}
