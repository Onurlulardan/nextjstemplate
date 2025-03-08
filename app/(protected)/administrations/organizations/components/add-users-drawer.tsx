'use client';

import { useState, useEffect } from 'react';
import { Drawer, Form, Select, Button } from 'antd';
import { Organization, User } from '@prisma/client';
import { getRequest, postRequest } from '@/lib/apiClient';

interface AddUsersDrawerProps {
  organization: Organization | null;
  open: boolean;
  onClose: () => void;
}

export function AddUsersDrawer({ organization, open, onClose }: AddUsersDrawerProps) {
  const [form] = Form.useForm();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (open) {
      fetchAvailableUsers();
    }
  }, [open]);

  const fetchAvailableUsers = async () => {
    try {
      const data = await getRequest('/administrations/users/available');
      setUsers(data);
    } catch (error) {
      console.error('Failed to fetch users:', error);
    }
  };

  const handleSubmit = async (values: { userIds: string[] }) => {
    if (!organization) return;

    try {
      setLoading(true);
      const result = await postRequest(
        `/administrations/organizations/${organization.id}/add-users`,
        { userIds: values.userIds }
      );
      form.resetFields();
      onClose();
      return result;
    } catch (error) {
      console.error('Failed to add users:', error);
    } finally {
      setLoading(false);
    }
  };

  if (!organization) return null;

  return (
    <Drawer
      title={`Add Users to ${organization.name}`}
      placement="right"
      onClose={onClose}
      open={open}
      width={720}
    >
      <Form form={form} layout="vertical" onFinish={handleSubmit}>
        <Form.Item
          name="userIds"
          label="Select Users"
          rules={[{ required: true, message: 'Please select users' }]}
        >
          <Select
            mode="multiple"
            placeholder="Select users to add"
            style={{ width: '100%' }}
            optionFilterProp="children"
            loading={!users.length}
          >
            {users.map((user) => (
              <Select.Option key={user.id} value={user.id}>
                {user.firstName} {user.lastName} ({user.email})
              </Select.Option>
            ))}
          </Select>
        </Form.Item>

        <Form.Item>
          <Button type="primary" htmlType="submit" loading={loading} block>
            Add Users
          </Button>
        </Form.Item>
      </Form>
    </Drawer>
  );
}
