'use client';

import { useEffect, useState } from 'react';
import {
  Card,
  Button,
  Typography,
  Tabs,
  TabsProps,
  Drawer,
  Modal,
  Dropdown,
  MenuProps,
} from 'antd';
import {
  PlusOutlined,
  SafetyCertificateOutlined,
  AppstoreOutlined,
  ThunderboltOutlined,
  EditOutlined,
  DeleteOutlined,
  MoreOutlined,
} from '@ant-design/icons';
import { usePermission } from '@/lib/auth/permissions';
import { DataGrid } from '@/core/components/datagrid';
import { Permission, Resource, Action } from '@prisma/client';
import { PermissionForm } from './components/permission-form';
import { ResourceForm } from './components/resource-form';
import { ActionForm } from './components/action-form';
import { getRequest, postRequest, putRequest, deleteRequest } from '@/lib/apiClient';

const { Title } = Typography;

// Types with relations
interface PermissionWithRelations extends Permission {
  resource: Resource;
  actions: {
    action: Action;
  }[];
  user?: {
    id: string;
    email: string;
    firstName: string | null;
    lastName: string | null;
  } | null;
  role?: {
    id: string;
    name: string;
    organizationId: string | null;
  } | null;
  organization?: {
    id: string;
    name: string;
  } | null;
}

interface ResourceWithCount extends Resource {
  _count: {
    permissions: number;
  };
}

interface ActionWithCount extends Action {
  _count: {
    permissions: number;
  };
}

export default function PermissionsPage() {
  // States for each tab
  const [permissions, setPermissions] = useState<PermissionWithRelations[]>([]);
  const [resources, setResources] = useState<Resource[]>([]);
  const [actions, setActions] = useState<Action[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('permissions');

  // Form states
  const [permissionDrawerVisible, setPermissionDrawerVisible] = useState(false);
  const [resourceDrawerVisible, setResourceDrawerVisible] = useState(false);
  const [actionDrawerVisible, setActionDrawerVisible] = useState(false);
  const [selectedPermission, setSelectedPermission] = useState<PermissionWithRelations | null>(
    null
  );
  const [selectedResource, setSelectedResource] = useState<Resource | null>(null);
  const [selectedAction, setSelectedAction] = useState<Action | null>(null);
  const [formLoading, setFormLoading] = useState(false);

  // Delete modal states
  const [deleteModalVisible, setDeleteModalVisible] = useState(false);
  const [itemToDelete, setItemToDelete] = useState<{
    type: 'permission' | 'resource' | 'action';
    id: string;
  } | null>(null);

  // Permission hooks
  const canViewPermissions = usePermission('permission', 'view');
  const canCreatePermission = usePermission('permission', 'create');
  const canEditPermission = usePermission('permission', 'edit');
  const canDeletePermission = usePermission('permission', 'delete');

  const canViewResources = usePermission('resource', 'view');
  const canCreateResource = usePermission('resource', 'create');
  const canEditResource = usePermission('resource', 'edit');
  const canDeleteResource = usePermission('resource', 'delete');

  const canViewActions = usePermission('action', 'view');
  const canCreateAction = usePermission('action', 'create');
  const canEditAction = usePermission('action', 'edit');
  const canDeleteAction = usePermission('action', 'delete');

  useEffect(() => {
    fetchData();
  }, [activeTab]);

  const fetchData = async () => {
    setLoading(true);
    try {
      if (activeTab === 'permissions') {
        const data = await getRequest<PermissionWithRelations[]>('/administrations/permissions');
        setPermissions(data);
      } else if (activeTab === 'resources') {
        const data = await getRequest<Resource[]>('/administrations/resources');
        setResources(data);
      } else if (activeTab === 'actions') {
        const data = await getRequest<Action[]>('/administrations/actions');
        setActions(data);
      }
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (values: any) => {
    setFormLoading(true);
    try {
      let endpoint = '';

      if (activeTab === 'permissions') {
        endpoint = selectedPermission
          ? `/administrations/permissions/${selectedPermission.id}`
          : '/administrations/permissions';
      } else if (activeTab === 'resources') {
        endpoint = selectedResource
          ? `/administrations/resources/${selectedResource.id}`
          : '/administrations/resources';
      } else if (activeTab === 'actions') {
        endpoint = selectedAction
          ? `/administrations/actions/${selectedAction.id}`
          : '/administrations/actions';
      }

      if (selectedPermission || selectedResource || selectedAction) {
        await putRequest(endpoint, values);
      } else {
        await postRequest(endpoint, values);
      }

      closeDrawers();
      fetchData();
    } catch (error) {
      console.error(error);
    } finally {
      setFormLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!itemToDelete) return;

    try {
      await deleteRequest(`/administrations/${itemToDelete.type}s/${itemToDelete.id}`);
      setDeleteModalVisible(false);
      setItemToDelete(null);
      fetchData();
    } catch (error) {
      console.error(error);
    }
  };

  const closeDrawers = () => {
    setPermissionDrawerVisible(false);
    setResourceDrawerVisible(false);
    setActionDrawerVisible(false);
    setSelectedPermission(null);
    setSelectedResource(null);
    setSelectedAction(null);
  };

  // Permission columns
  const permissionColumns = [
    {
      title: 'Actions',
      key: 'actions',
      width: 100,
      render: (record: PermissionWithRelations) => {
        const menuItems: MenuProps['items'] = [];

        if (canEditPermission) {
          menuItems.push({
            key: 'edit',
            label: 'Edit',
            icon: <EditOutlined />,
            onClick: () => {
              setSelectedPermission(record);
              setPermissionDrawerVisible(true);
            },
          });
        }

        if (canDeletePermission) {
          menuItems.push({
            key: 'delete',
            label: 'Delete',
            icon: <DeleteOutlined />,
            danger: true,
            onClick: () => {
              setItemToDelete({ type: 'permission', id: record.id });
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
      title: 'Resource',
      key: 'resource',
      render: (record: PermissionWithRelations) => record.resource.name,
    },
    {
      title: 'Target Type',
      dataIndex: 'target',
      key: 'target',
    },
    {
      title: 'Target',
      key: 'targetName',
      render: (record: PermissionWithRelations) => {
        if (record.user) {
          return `${record.user.firstName} ${record.user.lastName} (${record.user.email})`;
        }
        if (record.role) {
          return `${record.role.name}${record.role.organizationId ? ' (Organization Role)' : ' (Global Role)'}`;
        }
        if (record.organization) {
          return record.organization.name;
        }
        return '-';
      },
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (record: PermissionWithRelations) =>
        record.actions.map((pa) => pa.action.name).join(', '),
    },
  ];

  // Resource columns
  const resourceColumns = [
    {
      title: 'Actions',
      key: 'actions',
      width: 100,
      render: (record: Resource) => {
        const menuItems: MenuProps['items'] = [];

        if (canEditResource) {
          menuItems.push({
            key: 'edit',
            label: 'Edit',
            icon: <EditOutlined />,
            onClick: () => {
              setSelectedResource(record);
              setResourceDrawerVisible(true);
            },
          });
        }

        if (canDeleteResource) {
          menuItems.push({
            key: 'delete',
            label: 'Delete',
            icon: <DeleteOutlined />,
            danger: true,
            onClick: () => {
              setItemToDelete({ type: 'resource', id: record.id });
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
      title: 'Description',
      dataIndex: 'description',
      key: 'description',
    },
  ];

  // Action columns
  const actionColumns = [
    {
      title: 'Actions',
      key: 'actions',
      width: 100,
      render: (record: Action) => {
        const menuItems: MenuProps['items'] = [];

        if (canEditAction) {
          menuItems.push({
            key: 'edit',
            label: 'Edit',
            icon: <EditOutlined />,
            onClick: () => {
              setSelectedAction(record);
              setActionDrawerVisible(true);
            },
          });
        }

        if (canDeleteAction) {
          menuItems.push({
            key: 'delete',
            label: 'Delete',
            icon: <DeleteOutlined />,
            danger: true,
            onClick: () => {
              setItemToDelete({ type: 'action', id: record.id });
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
      title: 'Description',
      dataIndex: 'description',
      key: 'description',
    },
  ];

  const items: TabsProps['items'] = [
    {
      key: 'permissions',
      label: (
        <span>
          <SafetyCertificateOutlined />
          Permissions
        </span>
      ),
      children: (
        <DataGrid<PermissionWithRelations>
          columns={permissionColumns}
          dataSource={permissions}
          loading={loading}
          rowKey="id"
          headerContent={
            <div className="flex justify-between items-center mb-4">
              <Title level={4}>Permissions</Title>
              {canCreatePermission && (
                <Button
                  type="primary"
                  icon={<PlusOutlined />}
                  onClick={() => {
                    setSelectedPermission(null);
                    setPermissionDrawerVisible(true);
                  }}
                >
                  Create Permission
                </Button>
              )}
            </div>
          }
          onRowDoubleClick={
            canEditPermission
              ? (record) => {
                  setSelectedPermission(record);
                  setPermissionDrawerVisible(true);
                }
              : undefined
          }
        />
      ),
    },
    {
      key: 'resources',
      label: (
        <span>
          <AppstoreOutlined />
          Resources
        </span>
      ),
      children: (
        <DataGrid<Resource>
          columns={resourceColumns}
          dataSource={resources}
          loading={loading}
          rowKey="id"
          headerContent={
            <div className="flex justify-between items-center mb-4">
              <Title level={4}>Resources</Title>
              {canCreateResource && (
                <Button
                  type="primary"
                  icon={<PlusOutlined />}
                  onClick={() => {
                    setSelectedResource(null);
                    setResourceDrawerVisible(true);
                  }}
                >
                  Create Resource
                </Button>
              )}
            </div>
          }
          onRowDoubleClick={
            canEditResource
              ? (record) => {
                  setSelectedResource(record);
                  setResourceDrawerVisible(true);
                }
              : undefined
          }
        />
      ),
    },
    {
      key: 'actions',
      label: (
        <span>
          <ThunderboltOutlined />
          Actions
        </span>
      ),
      children: (
        <DataGrid<Action>
          columns={actionColumns}
          dataSource={actions}
          loading={loading}
          rowKey="id"
          headerContent={
            <div className="flex justify-between items-center mb-4">
              <Title level={4}>Actions</Title>
              {canCreateAction && (
                <Button
                  type="primary"
                  icon={<PlusOutlined />}
                  onClick={() => {
                    setSelectedAction(null);
                    setActionDrawerVisible(true);
                  }}
                >
                  Create Action
                </Button>
              )}
            </div>
          }
          onRowDoubleClick={
            canEditAction
              ? (record) => {
                  setSelectedAction(record);
                  setActionDrawerVisible(true);
                }
              : undefined
          }
        />
      ),
    },
  ];

  return (
    <>
      <Card>
        <Tabs activeKey={activeTab} items={items} onChange={setActiveTab} />
      </Card>

      {/* Permission Drawer */}
      <Drawer
        title={`${selectedPermission ? 'Edit' : 'Create'} Permission`}
        width={720}
        open={permissionDrawerVisible}
        onClose={closeDrawers}
      >
        <PermissionForm
          initialValues={selectedPermission}
          onSubmit={handleSubmit}
          loading={formLoading}
        />
      </Drawer>

      {/* Resource Drawer */}
      <Drawer
        title={`${selectedResource ? 'Edit' : 'Create'} Resource`}
        width={720}
        open={resourceDrawerVisible}
        onClose={closeDrawers}
      >
        <ResourceForm
          initialValues={selectedResource}
          onSubmit={handleSubmit}
          loading={formLoading}
        />
      </Drawer>

      {/* Action Drawer */}
      <Drawer
        title={`${selectedAction ? 'Edit' : 'Create'} Action`}
        width={720}
        open={actionDrawerVisible}
        onClose={closeDrawers}
      >
        <ActionForm initialValues={selectedAction} onSubmit={handleSubmit} loading={formLoading} />
      </Drawer>

      {/* Delete Modal */}
      <Modal
        title={`Delete ${itemToDelete?.type}`}
        open={deleteModalVisible}
        onOk={handleDelete}
        onCancel={() => {
          setDeleteModalVisible(false);
          setItemToDelete(null);
        }}
        okText="Delete"
        okButtonProps={{
          danger: true,
          loading: loading,
        }}
      >
        <p>
          Are you sure you want to delete this {itemToDelete?.type}? This action cannot be undone.
        </p>
      </Modal>
    </>
  );
}
