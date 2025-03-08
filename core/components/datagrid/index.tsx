'use client';

import { Table, TableProps } from 'antd';
import { ReactNode } from 'react';

export interface DataGridProps<T> extends Omit<TableProps<T>, 'pagination'> {
  loading?: boolean;
  pageSize?: number;
  pageSizeOptions?: string[];
  showSizeChanger?: boolean;
  total?: number;
  onPageChange?: (page: number) => void;
  onPageSizeChange?: (pageSize: number) => void;
  headerContent?: ReactNode;
  onRowDoubleClick?: (record: T) => void;
}

export function DataGrid<T extends object>({
  loading = false,
  pageSize = 10,
  pageSizeOptions = ['10', '20', '50', '100'],
  showSizeChanger = true,
  total,
  onPageChange,
  onPageSizeChange,
  headerContent,
  onRowDoubleClick,
  ...tableProps
}: DataGridProps<T>) {
  return (
    <div>
      {headerContent && <div style={{ marginBottom: 16 }}>{headerContent}</div>}
      <Table<T>
        {...tableProps}
        loading={loading}
        onRow={
          onRowDoubleClick
            ? (record) => ({
                onDoubleClick: () => onRowDoubleClick(record),
                style: { cursor: 'pointer' },
              })
            : undefined
        }
        pagination={{
          defaultPageSize: pageSize,
          showSizeChanger,
          showTotal: (total) => `Total ${total} items`,
          pageSizeOptions,
          size: 'default',
          className: 'pagination-with-pagesize-left',
          total,
          onChange: onPageChange,
          onShowSizeChange: (_, size) => onPageSizeChange?.(size),
        }}
      />
    </div>
  );
}
