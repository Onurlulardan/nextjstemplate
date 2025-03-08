'use client';

import { useEffect } from 'react';
import { Form, Input, Button, Space } from 'antd';
import { Action } from '@prisma/client';

interface ActionFormProps {
  initialValues?: Action | null;
  onSubmit: (values: any) => Promise<void>;
  loading?: boolean;
}

export function ActionForm({ initialValues, onSubmit, loading }: ActionFormProps) {
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
        label="Action Name"
        rules={[
          { required: true, message: 'Please enter action name' },
          { min: 3, message: 'Action name must be at least 3 characters' },
        ]}
      >
        <Input placeholder="Enter action name (e.g., VIEW, CREATE)" />
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
        <Input placeholder="Enter slug (e.g., view, create)" />
      </Form.Item>

      <Form.Item name="description" label="Description">
        <Input.TextArea rows={4} placeholder="Enter action description" />
      </Form.Item>

      <Form.Item className="mb-0">
        <Space className="w-full justify-end">
          <Button onClick={() => form.resetFields()}>Reset</Button>
          <Button type="primary" htmlType="submit" loading={loading}>
            {initialValues ? 'Update' : 'Create'} Action
          </Button>
        </Space>
      </Form.Item>
    </Form>
  );
}
