'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useSession } from 'next-auth/react';
import {
  Button,
  Form,
  Input,
  Card,
  Typography,
  Avatar,
  Row,
  Col,
  Divider,
  Upload,
  Tabs,
} from 'antd';
import {
  UserOutlined,
  MailOutlined,
  PhoneOutlined,
  CameraOutlined,
  SaveOutlined,
  LockOutlined,
} from '@ant-design/icons';
import type { UploadChangeParam } from 'antd/es/upload';
import type { RcFile, UploadFile, UploadProps } from 'antd/es/upload/interface';
import { putRequest } from '@/lib/apiClient';

const { Title, Text } = Typography;

interface ProfileFormData {
  firstName: string;
  lastName: string;
  phone?: string;
  avatar?: string;
}

interface PasswordFormData {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

export default function ProfileEditPage() {
  const [loading, setLoading] = useState(false);
  const [avatarUrl, setAvatarUrl] = useState<string>();
  const router = useRouter();
  const { data: session, update: updateSession } = useSession();

  const handleProfileSubmit = async (values: ProfileFormData) => {
    setLoading(true);
    try {
      const updatedUser = await putRequest('/administrations/profile', {
        ...values,
        avatar: avatarUrl,
      });

      await updateSession({
        ...session,
        user: {
          ...session?.user,
          firstName: updatedUser.firstName,
          lastName: updatedUser.lastName,
          avatar: updatedUser.avatar,
          phone: updatedUser.phone,
        },
      });

      router.refresh();
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordSubmit = async (values: PasswordFormData) => {
    setLoading(true);
    try {
      await putRequest('/administrations/profile/password', {
        currentPassword: values.currentPassword,
        newPassword: values.newPassword,
      });

      router.refresh();
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleAvatarChange: UploadProps['onChange'] = async (
    info: UploadChangeParam<UploadFile>
  ) => {
    if (info.file.status === 'done') {
      setAvatarUrl(info.file.response.url);
    }
  };

  if (!session?.user) {
    return null;
  }

  return (
    <div className="max-w-[1000px] mx-auto p-6">
      <Card>
        <Row gutter={[24, 24]}>
          {/* Sol Taraf - Avatar ve Temel Bilgiler */}
          <Col xs={24} md={8}>
            <div className="flex justify-center items-center  h-full">
              <div className="text-center">
                <Upload
                  name="avatar"
                  listType="picture-circle"
                  showUploadList={false}
                  action="/api/administrations/upload"
                  onChange={handleAvatarChange}
                >
                  {avatarUrl || session.user.avatar ? (
                    <Avatar size={120} src={avatarUrl || session.user.avatar} alt="avatar" />
                  ) : (
                    <div>
                      <CameraOutlined className="text-2xl" />
                      <div className="mt-2">Upload</div>
                    </div>
                  )}
                </Upload>
                <Title level={4} className="mt-4 mb-1">
                  {session.user.firstName} {session.user.lastName}
                </Title>
                <Text type="secondary">{session.user.email}</Text>
              </div>
            </div>
          </Col>

          {/* Sağ Taraf - Tabs */}
          <Col xs={24} md={16}>
            <Tabs
              defaultActiveKey="profile"
              items={[
                {
                  key: 'profile',
                  label: 'Profile Settings',
                  children: (
                    <Form
                      layout="vertical"
                      initialValues={{
                        firstName: session.user.firstName || '',
                        lastName: session.user.lastName || '',
                        email: session.user.email,
                        phone: session.user.phone || '',
                      }}
                      onFinish={handleProfileSubmit}
                    >
                      <Row gutter={16}>
                        <Col xs={24} sm={12}>
                          <Form.Item
                            name="firstName"
                            label="First Name"
                            rules={[{ required: true, message: 'Please enter your first name' }]}
                          >
                            <Input prefix={<UserOutlined />} placeholder="First Name" />
                          </Form.Item>
                        </Col>
                        <Col xs={24} sm={12}>
                          <Form.Item
                            name="lastName"
                            label="Last Name"
                            rules={[{ required: true, message: 'Please enter your last name' }]}
                          >
                            <Input prefix={<UserOutlined />} placeholder="Last Name" />
                          </Form.Item>
                        </Col>
                      </Row>

                      <Form.Item name="email" label="Email">
                        <Input prefix={<MailOutlined />} disabled />
                      </Form.Item>

                      <Form.Item
                        name="phone"
                        label="Phone Number"
                        rules={[
                          {
                            pattern: /^[0-9+\-\s()]*$/,
                            message: 'Please enter a valid phone number',
                          },
                        ]}
                      >
                        <Input prefix={<PhoneOutlined />} placeholder="Phone Number" />
                      </Form.Item>

                      <Form.Item>
                        <Button
                          type="primary"
                          htmlType="submit"
                          loading={loading}
                          icon={<SaveOutlined />}
                          size="large"
                          block
                        >
                          Save Changes
                        </Button>
                      </Form.Item>
                    </Form>
                  ),
                },
                {
                  key: 'password',
                  label: 'Change Password',
                  children: (
                    <Form layout="vertical" onFinish={handlePasswordSubmit}>
                      <Form.Item
                        name="currentPassword"
                        label="Current Password"
                        rules={[{ required: true, message: 'Please enter your current password' }]}
                      >
                        <Input.Password prefix={<LockOutlined />} placeholder="Current Password" />
                      </Form.Item>

                      <Form.Item
                        name="newPassword"
                        label="New Password"
                        rules={[
                          { required: true, message: 'Please enter your new password' },
                          { min: 8, message: 'Password must be at least 8 characters' },
                        ]}
                      >
                        <Input.Password prefix={<LockOutlined />} placeholder="New Password" />
                      </Form.Item>

                      <Form.Item
                        name="confirmPassword"
                        label="Confirm Password"
                        dependencies={['newPassword']}
                        rules={[
                          { required: true, message: 'Please confirm your new password' },
                          ({ getFieldValue }) => ({
                            validator(_, value) {
                              if (!value || getFieldValue('newPassword') === value) {
                                return Promise.resolve();
                              }
                              return Promise.reject(new Error('The two passwords do not match'));
                            },
                          }),
                        ]}
                      >
                        <Input.Password prefix={<LockOutlined />} placeholder="Confirm Password" />
                      </Form.Item>

                      <Form.Item>
                        <Button
                          type="primary"
                          htmlType="submit"
                          loading={loading}
                          icon={<LockOutlined />}
                          size="large"
                          block
                        >
                          Update Password
                        </Button>
                      </Form.Item>
                    </Form>
                  ),
                },
              ]}
            />
          </Col>
        </Row>
      </Card>
    </div>
  );
}
