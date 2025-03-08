'use client';

import { useEffect, useState } from 'react';
import { Card, Button, Tag, Typography, Dropdown, MenuProps, Drawer, Modal } from 'antd';
import { PlusOutlined, EditOutlined, DeleteOutlined, MoreOutlined } from '@ant-design/icons';
import { useRouter } from 'next/navigation';
import { usePermission } from '@/lib/auth/permissions';
import { DataGrid } from '@/core/components/datagrid';
import { UserForm } from './components/user-form';
import { User, UserStatus } from '@prisma/client';
import { getRequest, postRequest, putRequest, deleteRequest } from '@/lib/apiClient';

const { Title } = Typography;

// Role Type Definition
type Role = {
  id: string;
  name: string;
  description: string;
};

// UserRole Type Definition
type UserRole = {
  role: Role;
};

// User Type Definition (without password)
type UserWithoutPassword = Omit<User, 'password'> & {
  userRoles?: UserRole[];
};

export default function UsersPage() {
  const [users, setUsers] = useState<UserWithoutPassword[]>([]);
  const [loading, setLoading] = useState(true);
  const [drawerVisible, setDrawerVisible] = useState(false);
  const [selectedUser, setSelectedUser] = useState<UserWithoutPassword | null>(null);
  const [formLoading, setFormLoading] = useState(false);
  const [deleteModalVisible, setDeleteModalVisible] = useState(false);
  const [userToDelete, setUserToDelete] = useState<UserWithoutPassword | null>(null);
  const router = useRouter();

  // Permission hooks
  const canCreate = usePermission('user', 'create');
  const canEdit = usePermission('user', 'edit');
  const canDelete = usePermission('user', 'delete');

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const data = await getRequest<UserWithoutPassword[]>('/administrations/users');
      setUsers(data);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!userToDelete) return;

    try {
      await deleteRequest(`/administrations/users/${userToDelete.id}`);
      setDeleteModalVisible(false);
      setUserToDelete(null);
      fetchUsers();
    } catch (error) {
      console.error(error);
    }
  };

  const handleSubmit = async (values: any) => {
    setFormLoading(true);
    try {
      const endpoint = selectedUser
        ? `/administrations/users/${selectedUser.id}`
        : '/administrations/users';

      if (selectedUser) {
        await putRequest(endpoint, values);
      } else {
        await postRequest(endpoint, values);
      }

      setDrawerVisible(false);
      setSelectedUser(null);
      fetchUsers();
    } catch (error) {
      console.error(error);
    } finally {
      setFormLoading(false);
    }
  };

  const columns = [
    {
      title: 'Actions',
      key: 'actions',
      width: 100,
      render: (record: UserWithoutPassword) => {
        const menuItems: MenuProps['items'] = [];

        if (canEdit) {
          menuItems.push({
            key: 'edit',
            label: 'Edit',
            icon: <EditOutlined />,
            onClick: () => {
              setSelectedUser(record);
              setDrawerVisible(true);
            },
          });
        }

        if (canDelete) {
          menuItems.push({
            key: 'delete',
            label: 'Delete',
            icon: <DeleteOutlined />,
            danger: true,
            onClick: () => {
              setUserToDelete(record);
              setDeleteModalVisible(true);
            },
          });
        }

        return (
          <Dropdown menu={{ items: menuItems }} trigger={['click']} placement="bottomRight">
            <Button type="text" icon={<MoreOutlined />} />
          </Dropdown>
        );
      },
    },
    {
      title: 'Name',
      key: 'name',
      render: (record: UserWithoutPassword) => (
        <span>
          {record.firstName && record.lastName
            ? `${record.firstName} ${record.lastName}`
            : record.email}
        </span>
      ),
    },
    {
      title: 'Email',
      dataIndex: 'email',
      key: 'email',
    },
    {
      title: 'Roles',
      key: 'roles',
      render: (record: UserWithoutPassword) => (
        <>
          {record.userRoles && record.userRoles.length > 0 ? (
            record.userRoles.map((userRole, index) => (
              <Tag 
                key={index} 
                color={userRole.role.name === 'ADMIN' ? 'blue' : 'green'}
                style={{ marginRight: 4, marginBottom: 4 }}
              >
                {userRole.role.name}
              </Tag>
            ))
          ) : (
            <Tag>No Role</Tag>
          )}
        </>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status: UserStatus) => (
        <Tag color={status === 'ACTIVE' ? 'green' : 'red'}>{status}</Tag>
      ),
    },
  ];

  const headerContent = (
    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 24 }}>
      <Title level={2}>Users</Title>
      {canCreate && (
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => {
            setSelectedUser(null);
            setDrawerVisible(true);
          }}
        >
          Create User
        </Button>
      )}
    </div>
  );

  return (
    <>
      <Card>
        <DataGrid<UserWithoutPassword>
          columns={columns}
          dataSource={users}
          rowKey="id"
          loading={loading}
          headerContent={headerContent}
          onRowDoubleClick={
            canEdit
              ? (record) => {
                  setSelectedUser(record);
                  setDrawerVisible(true);
                }
              : undefined
          }
        />
      </Card>

      <Drawer
        title={selectedUser ? 'Edit User' : 'Create User'}
        open={drawerVisible}
        onClose={() => {
          setDrawerVisible(false);
          setSelectedUser(null);
        }}
        width={720}
      >
        <UserForm
          initialValues={selectedUser ? {
            ...selectedUser,
            userRoles: selectedUser.userRoles
          } : undefined}
          onSubmit={handleSubmit}
          loading={formLoading}
        />
      </Drawer>

      <Modal
        title="Delete User"
        open={deleteModalVisible}
        onOk={handleDelete}
        onCancel={() => {
          setDeleteModalVisible(false);
          setUserToDelete(null);
        }}
        okText="Delete"
        cancelText="Cancel"
        okButtonProps={{ danger: true }}
        centered
      >
        <p>Are you sure you want to delete this user?</p>
        {userToDelete && (
          <p>
            <strong>
              {userToDelete.firstName && userToDelete.lastName
                ? `${userToDelete.firstName} ${userToDelete.lastName}`
                : userToDelete.email}
            </strong>
          </p>
        )}
      </Modal>
    </>
  );
}
