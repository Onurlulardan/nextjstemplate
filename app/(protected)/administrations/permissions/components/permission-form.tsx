'use client';

import { useEffect, useState } from 'react';
import { Form, Select, Button, Space } from 'antd';
import { Permission, Resource, Action, PermissionTarget } from '@prisma/client';
import { getRequest } from '@/lib/apiClient';

interface User {
  id: string;
  email: string;
  firstName: string | null;
  lastName: string | null;
}

interface Role {
  id: string;
  name: string;
  organizationId: string | null;
}

interface Organization {
  id: string;
  name: string;
}

interface PermissionWithRelations extends Permission {
  resource: Resource;
  actions: {
    action: Action;
  }[];
  user?: User | null;
  role?: Role | null;
  organization?: Organization | null;
}

interface PermissionFormProps {
  initialValues?: PermissionWithRelations | null;
  onSubmit: (values: any) => Promise<void>;
  loading?: boolean;
}

export function PermissionForm({ initialValues, onSubmit, loading }: PermissionFormProps) {
  const [form] = Form.useForm();
  const [targetType, setTargetType] = useState<PermissionTarget | null>(null);
  const [loadingData, setLoadingData] = useState(true);
  const [formData, setFormData] = useState<{
    resources: Resource[];
    actions: Action[];
    users: User[];
    roles: Role[];
    organizations: Organization[];
  }>({
    resources: [],
    actions: [],
    users: [],
    roles: [],
    organizations: [],
  });

  useEffect(() => {
    fetchFormData();
  }, []);

  useEffect(() => {
    form.resetFields();
    if (initialValues) {
      form.setFieldsValue({
        resourceId: initialValues.resourceId,
        target: initialValues.target,
        userId: initialValues.user?.id,
        roleId: initialValues.role?.id,
        organizationId: initialValues.organization?.id,
        actionIds: initialValues.actions?.map((pa) => pa.action.id),
      });
      setTargetType(initialValues.target);
    }
  }, [form, initialValues]);

  const fetchFormData = async () => {
    setLoadingData(true);
    try {
      const [resources, actions, users, roles, organizations] = await Promise.all([
        getRequest<Resource[]>('/administrations/resources'),
        getRequest<Action[]>('/administrations/actions'),
        getRequest<User[]>('/administrations/users'),
        getRequest<Role[]>('/administrations/roles'),
        getRequest<Organization[]>('/administrations/organizations'),
      ]);

      setFormData({
        resources,
        actions,
        users,
        roles,
        organizations,
      });
    } catch (error) {
      console.error('Error fetching form data:', error);
    } finally {
      setLoadingData(false);
    }
  };

  const handleSubmit = async (values: any) => {
    try {
      await onSubmit(values);
      form.resetFields();
      setTargetType(null);
    } catch (error) {
      console.error('Error submitting form:', error);
    }
  };

  const handleTargetTypeChange = (value: PermissionTarget) => {
    setTargetType(value);
    form.setFieldsValue({
      userId: undefined,
      roleId: undefined,
      organizationId: undefined,
    });
  };

  return (
    <Form form={form} layout="vertical" onFinish={handleSubmit} disabled={loadingData}>
      <Form.Item
        name="resourceId"
        label="Resource"
        rules={[{ required: true, message: 'Please select a resource' }]}
      >
        <Select
          placeholder="Select resource"
          loading={loadingData}
          options={formData.resources.map((resource) => ({
            label: `${resource.name} (${resource.slug})`,
            value: resource.id,
          }))}
          showSearch
          optionFilterProp="label"
        />
      </Form.Item>

      <Form.Item
        name="target"
        label="Target Type"
        rules={[{ required: true, message: 'Please select a target type' }]}
      >
        <Select
          placeholder="Select target type"
          onChange={handleTargetTypeChange}
          options={[
            { label: 'User', value: 'USER' },
            { label: 'Role', value: 'ROLE' },
            { label: 'Organization', value: 'ORGANIZATION' },
          ]}
        />
      </Form.Item>

      {targetType === 'USER' && (
        <Form.Item
          name="userId"
          label="User"
          rules={[{ required: true, message: 'Please select a user' }]}
        >
          <Select
            placeholder="Select user"
            loading={loadingData}
            options={formData.users.map((user) => ({
              label: `${user.firstName} ${user.lastName} (${user.email})`,
              value: user.id,
            }))}
            showSearch
            optionFilterProp="label"
          />
        </Form.Item>
      )}

      {targetType === 'ROLE' && (
        <Form.Item
          name="roleId"
          label="Role"
          rules={[{ required: true, message: 'Please select a role' }]}
        >
          <Select
            placeholder="Select role"
            loading={loadingData}
            options={formData.roles.map((role) => ({
              label: `${role.name}${role.organizationId ? ' (Organization Role)' : ' (Global Role)'}`,
              value: role.id,
            }))}
            showSearch
            optionFilterProp="label"
          />
        </Form.Item>
      )}

      {targetType === 'ORGANIZATION' && (
        <Form.Item
          name="organizationId"
          label="Organization"
          rules={[{ required: true, message: 'Please select an organization' }]}
        >
          <Select
            placeholder="Select organization"
            loading={loadingData}
            options={formData.organizations.map((org) => ({
              label: org.name,
              value: org.id,
            }))}
            showSearch
            optionFilterProp="label"
          />
        </Form.Item>
      )}

      <Form.Item
        name="actionIds"
        label="Actions"
        rules={[{ required: true, message: 'Please select at least one action' }]}
      >
        <Select
          placeholder="Select actions"
          mode="multiple"
          loading={loadingData}
          options={formData.actions.map((action) => ({
            label: `${action.name} (${action.slug})`,
            value: action.id,
          }))}
          showSearch
          optionFilterProp="label"
        />
      </Form.Item>

      <Form.Item className="mb-0">
        <Space className="w-full justify-end">
          <Button onClick={() => form.resetFields()}>Reset</Button>
          <Button type="primary" htmlType="submit" loading={loading}>
            {initialValues ? 'Update' : 'Create'} Permission
          </Button>
        </Space>
      </Form.Item>
    </Form>
  );
}
