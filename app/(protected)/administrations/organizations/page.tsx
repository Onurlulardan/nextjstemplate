'use client';

import { useEffect, useState } from 'react';
import { Card, Button, Tag, Typography, Dropdown, MenuProps, Drawer, Modal } from 'antd';
import { PlusOutlined, EditOutlined, DeleteOutlined, MoreOutlined } from '@ant-design/icons';
import { useRouter } from 'next/navigation';
import { usePermission } from '@/lib/auth/permissions';
import { DataGrid } from '@/core/components/datagrid';
import { Organization, OrgStatus } from '@prisma/client';
import { OrganizationForm } from './components/organization-form';
import { AddUsersDrawer } from './components/add-users-drawer';
import { getRequest, deleteRequest, postRequest, putRequest } from '@/lib/apiClient';

const { Title } = Typography;

export default function OrganizationsPage() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);
  const [drawerVisible, setDrawerVisible] = useState(false);
  const [addUsersDrawerOpen, setAddUsersDrawerOpen] = useState(false);
  const [selectedOrg, setSelectedOrg] = useState<Organization | null>(null);
  const [formLoading, setFormLoading] = useState(false);
  const [deleteModalVisible, setDeleteModalVisible] = useState(false);
  const [orgToDelete, setOrgToDelete] = useState<Organization | null>(null);
  const router = useRouter();

  // Permission hooks
  const canCreate = usePermission('organization', 'create');
  const canEdit = usePermission('organization', 'edit');
  const canDelete = usePermission('organization', 'delete');
  const canAddUsers = usePermission('organization', 'update');

  useEffect(() => {
    fetchOrganizations();
  }, []);

  const fetchOrganizations = async () => {
    try {
      const data = await getRequest<Organization[]>('/administrations/organizations');
      const rootOrgs = data.filter((org) => !org.parentId);
      setOrganizations(rootOrgs);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!orgToDelete) return;

    try {
      await deleteRequest(`/administrations/organizations/${orgToDelete.id}`);
      setDeleteModalVisible(false);
      setOrgToDelete(null);
      fetchOrganizations();
    } catch (error) {
      console.error(error);
    }
  };

  const handleSubmit = async (values: any) => {
    setFormLoading(true);
    try {
      if (selectedOrg) {
        await putRequest(`/administrations/organizations/${selectedOrg.id}`, values);
      } else {
        await postRequest('/administrations/organizations', values);
      }

      setDrawerVisible(false);
      setSelectedOrg(null);
      fetchOrganizations();
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
      render: (record: Organization) => {
        const menuItems: MenuProps['items'] = [];

        if (canEdit) {
          menuItems.push({
            key: 'edit',
            label: 'Edit',
            icon: <EditOutlined />,
            onClick: () => {
              setSelectedOrg(record);
              setDrawerVisible(true);
            },
          });
        }

        if (canAddUsers) {
          menuItems.push({
            key: 'addUsers',
            label: 'Add Users',
            icon: <PlusOutlined />,
            onClick: () => {
              setSelectedOrg(record);
              setAddUsersDrawerOpen(true);
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
              setOrgToDelete(record);
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
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: 'Slug',
      dataIndex: 'slug',
      key: 'slug',
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status: OrgStatus) => (
        <Tag color={status === 'ACTIVE' ? 'green' : status === 'INACTIVE' ? 'orange' : 'red'}>
          {status}
        </Tag>
      ),
    },
    {
      title: 'Members',
      key: 'members',
      render: (record: any) => record._count?.members || 0,
    },
  ];

  const headerContent = (
    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 24 }}>
      <Title level={2}>Organizations</Title>
      {canCreate && (
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => {
            setSelectedOrg(null);
            setDrawerVisible(true);
          }}
        >
          Create Organization
        </Button>
      )}
    </div>
  );

  return (
    <>
      <Card>
        {headerContent}
        <DataGrid
          columns={columns}
          dataSource={organizations}
          loading={loading}
          rowKey={(record) => `org-${record.id}`}
          expandable={{
            defaultExpandAllRows: true,
            childrenColumnName: 'children',
          }}
          onRowDoubleClick={
            canEdit
              ? (record) => {
                  setSelectedOrg(record);
                  setDrawerVisible(true);
                }
              : undefined
          }
        />
      </Card>

      <Drawer
        title={selectedOrg ? 'Edit Organization' : 'Create Organization'}
        width={720}
        open={drawerVisible}
        onClose={() => {
          setDrawerVisible(false);
          setSelectedOrg(null);
        }}
        destroyOnClose
      >
        <OrganizationForm
          initialValues={selectedOrg || undefined}
          onSubmit={handleSubmit}
          loading={formLoading}
        />
      </Drawer>

      <AddUsersDrawer
        organization={selectedOrg}
        open={addUsersDrawerOpen}
        onClose={() => {
          setAddUsersDrawerOpen(false);
          setSelectedOrg(null);
        }}
      />

      <Modal
        title="Delete Organization"
        open={deleteModalVisible}
        onOk={handleDelete}
        onCancel={() => {
          setDeleteModalVisible(false);
          setOrgToDelete(null);
        }}
        okText="Delete"
        okButtonProps={{ danger: true }}
      >
        <p>Are you sure you want to delete this organization? This action cannot be undone.</p>
      </Modal>
    </>
  );
}
