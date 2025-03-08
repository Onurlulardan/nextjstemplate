'use client';

import { useEffect, useState } from 'react';
import { Card, Button, Tag, Typography, Dropdown, MenuProps, Drawer, Modal } from 'antd';
import { PlusOutlined, EditOutlined, DeleteOutlined, MoreOutlined } from '@ant-design/icons';
import { useRouter } from 'next/navigation';
import { usePermission } from '@/lib/auth/permissions';
import { DataGrid } from '@/core/components/datagrid';
import { Role, Organization } from '@prisma/client';
import { RoleForm } from './components/role-form';
import { getRequest, postRequest, putRequest, deleteRequest } from '@/lib/apiClient';

const { Title } = Typography;

interface RoleWithRelations extends Role {
  organization?: {
    id: string;
    name: string;
    slug: string;
  } | null;
  _count?: {
    userRoles: number;
  };
}

export default function RolesPage() {
  const [roles, setRoles] = useState<RoleWithRelations[]>([]);
  const [loading, setLoading] = useState(true);
  const [drawerVisible, setDrawerVisible] = useState(false);
  const [selectedRole, setSelectedRole] = useState<RoleWithRelations | null>(null);
  const [formLoading, setFormLoading] = useState(false);
  const [deleteModalVisible, setDeleteModalVisible] = useState(false);
  const [roleToDelete, setRoleToDelete] = useState<RoleWithRelations | null>(null);
  const router = useRouter();

  // Permission hooks
  const canCreate = usePermission('role', 'create');
  const canEdit = usePermission('role', 'edit');
  const canDelete = usePermission('role', 'delete');

  useEffect(() => {
    fetchRoles();
  }, []);

  const fetchRoles = async () => {
    try {
      const data = await getRequest<RoleWithRelations[]>('/administrations/roles');
      setRoles(data);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!roleToDelete) return;

    try {
      await deleteRequest(`/administrations/roles/${roleToDelete.id}`);
      setDeleteModalVisible(false);
      setRoleToDelete(null);
      fetchRoles();
    } catch (error) {
      console.error(error);
    }
  };

  const handleSubmit = async (values: any) => {
    setFormLoading(true);
    try {
      const endpoint = selectedRole
        ? `/administrations/roles/${selectedRole.id}`
        : '/administrations/roles';

      if (selectedRole) {
        await putRequest(endpoint, values);
      } else {
        await postRequest(endpoint, values);
      }

      setDrawerVisible(false);
      setSelectedRole(null);
      fetchRoles();
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
      render: (text: string, record: RoleWithRelations) => {
        const items: MenuProps['items'] = [
          {
            key: 'edit',
            icon: <EditOutlined />,
            label: 'Edit',
            disabled: !canEdit,
            onClick: () => {
              setSelectedRole(record);
              setDrawerVisible(true);
            },
          },
          {
            key: 'delete',
            icon: <DeleteOutlined />,
            label: 'Delete',
            disabled: !canDelete,
            danger: true,
            onClick: () => {
              setRoleToDelete(record);
              setDeleteModalVisible(true);
            },
          },
        ];

        return (
          <Dropdown menu={{ items }} trigger={['click']} placement="bottomRight">
            <Button type="text" icon={<MoreOutlined />} />
          </Dropdown>
        );
      },
    },
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      sorter: (a: RoleWithRelations, b: RoleWithRelations) => a.name.localeCompare(b.name),
    },
    {
      title: 'Description',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
    },
    {
      title: 'Organization',
      key: 'organization',
      render: (text: string, record: RoleWithRelations) => record.organization?.name || 'Global',
    },
    {
      title: 'Default',
      dataIndex: 'isDefault',
      key: 'isDefault',
      render: (isDefault: boolean) => (isDefault ? <Tag color="blue">Default</Tag> : null),
    },
    {
      title: 'Users',
      key: 'userRoles',
      render: (text: string, record: RoleWithRelations) => record._count?.userRoles || 0,
    },
  ];

  return (
    <div className="p-8">
      <Card>
        <div className="flex justify-between items-center mb-4">
          <Title level={3} className="!mb-0">
            Roles
          </Title>
          {canCreate && (
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => {
                setSelectedRole(null);
                setDrawerVisible(true);
              }}
            >
              Create Role
            </Button>
          )}
        </div>

        <DataGrid<RoleWithRelations>
          columns={columns}
          dataSource={roles}
          loading={loading}
          rowKey="id"
          onRowDoubleClick={
            canEdit
              ? (record) => {
                  setSelectedRole(record);
                  setDrawerVisible(true);
                }
              : undefined
          }
        />
      </Card>

      <Drawer
        title={`${selectedRole ? 'Edit' : 'Create'} Role`}
        width={720}
        onClose={() => {
          setDrawerVisible(false);
          setSelectedRole(null);
        }}
        open={drawerVisible}
        style={{ paddingBottom: 80 }}
      >
        <RoleForm initialValues={selectedRole} onSubmit={handleSubmit} loading={formLoading} />
      </Drawer>

      <Modal
        title="Delete Role"
        open={deleteModalVisible}
        onOk={handleDelete}
        onCancel={() => {
          setDeleteModalVisible(false);
          setRoleToDelete(null);
        }}
        okText="Delete"
        okButtonProps={{
          danger: true,
          loading: formLoading,
        }}
      >
        <p>Are you sure you want to delete this role?</p>
        <p>This action cannot be undone.</p>
      </Modal>
    </div>
  );
}
