'use client';

import { Form, Input, Select, Button } from 'antd';
import { Organization, OrgStatus } from '@prisma/client';
import { useEffect, useState } from 'react';
import { getRequest } from '@/lib/apiClient';

interface OrganizationFormProps {
  initialValues?: Organization;
  onSubmit: (values: any) => void;
  loading?: boolean;
}

export function OrganizationForm({ initialValues, onSubmit, loading }: OrganizationFormProps) {
  const [form] = Form.useForm();
  const [organizations, setOrganizations] = useState<Organization[]>([]);

  useEffect(() => {
    fetchAvailableParents();
  }, [initialValues]);

  const fetchAvailableParents = async () => {
    try {
      const url = initialValues
        ? `/administrations/organizations/available-parents?organizationId=${initialValues.id}`
        : '/administrations/organizations/available-parents';

      const data = await getRequest(url);
      setOrganizations(data);
    } catch (error) {
      console.error('Failed to fetch available parents:', error);
    }
  };

  useEffect(() => {
    if (initialValues) {
      form.setFieldsValue(initialValues);
    }
  }, [initialValues, form]);

  const handleSubmit = async (values: any) => {
    await onSubmit(values);
    form.resetFields();
  };

  return (
    <Form form={form} layout="vertical" onFinish={handleSubmit} initialValues={initialValues}>
      <Form.Item
        name="name"
        label="Name"
        rules={[{ required: true, message: 'Please enter organization name' }]}
      >
        <Input placeholder="Enter organization name" />
      </Form.Item>

      <Form.Item
        name="slug"
        label="Slug"
        rules={[
          { required: true, message: 'Please enter organization slug' },
          {
            pattern: /^[a-z0-9-]+$/,
            message: 'Slug can only contain lowercase letters, numbers, and hyphens',
          },
        ]}
      >
        <Input placeholder="Enter organization slug" />
      </Form.Item>

      <Form.Item
        name="status"
        label="Status"
        rules={[{ required: true, message: 'Please select organization status' }]}
      >
        <Select>
          {Object.values(OrgStatus).map((status) => (
            <Select.Option key={status} value={status}>
              {status}
            </Select.Option>
          ))}
        </Select>
      </Form.Item>

      <Form.Item name="parentId" label="Parent Organization">
        <Select allowClear placeholder="Select parent organization" loading={!organizations.length}>
          {organizations.map((org) => (
            <Select.Option key={org.id} value={org.id}>
              {org.name}
            </Select.Option>
          ))}
        </Select>
      </Form.Item>

      <Form.Item>
        <Button type="primary" htmlType="submit" loading={loading} block>
          {initialValues ? 'Update Organization' : 'Create Organization'}
        </Button>
      </Form.Item>
    </Form>
  );
}
