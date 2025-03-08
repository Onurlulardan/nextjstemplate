'use client';

import { useEffect } from 'react';
import { Form, Input, Button, Space } from 'antd';
import { Resource } from '@prisma/client';

interface ResourceFormProps {
  initialValues?: Resource | null;
  onSubmit: (values: any) => Promise<void>;
  loading?: boolean;
}

export function ResourceForm({ initialValues, onSubmit, loading }: ResourceFormProps) {
  const [form] = Form.useForm();

  useEffect(() => {
    form.resetFields();
    if (initialValues) {
      form.setFieldsValue({
        name: initialValues.name,
        slug: initialValues.slug,
        description: initialValues.description,
      });
    }
  }, [form, initialValues]);

  return (
    <Form form={form} layout="vertical" onFinish={onSubmit}>
      <Form.Item
        name="name"
        label="Resource Name"
        rules={[
          { required: true, message: 'Please enter resource name' },
          { min: 3, message: 'Resource name must be at least 3 characters' },
        ]}
      >
        <Input placeholder="Enter resource name (e.g., USER, PRODUCT)" />
      </Form.Item>

      <Form.Item
        name="slug"
        label="Slug"
        rules={[
          { required: true, message: 'Please enter slug' },
          {
            pattern: /^[a-z0-9-]+$/,
            message: 'Slug can only contain lowercase letters, numbers, and hyphens',
          },
        ]}
      >
        <Input placeholder="Enter slug (e.g., user, product)" />
      </Form.Item>

      <Form.Item name="description" label="Description">
        <Input.TextArea rows={4} placeholder="Enter resource description" />
      </Form.Item>

      <Form.Item className="mb-0">
        <Space className="w-full justify-end">
          <Button onClick={() => form.resetFields()}>Reset</Button>
          <Button type="primary" htmlType="submit" loading={loading}>
            {initialValues ? 'Update' : 'Create'} Resource
          </Button>
        </Space>
      </Form.Item>
    </Form>
  );
}
