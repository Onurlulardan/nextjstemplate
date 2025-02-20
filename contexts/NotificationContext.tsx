'use client';

import { createContext, useContext } from 'react';
import { notification } from 'antd';
import { NotificationInstance } from 'antd/es/notification/interface';
import { ShowNotificationFunction } from '@/lib/apiClient/types/types';

interface NotificationContextType {
  showNotification: ShowNotificationFunction;
  notificationApi: NotificationInstance;
}

const NotificationContext = createContext<NotificationContextType | null>(null);

export const NotificationProvider = ({ children }: { children: React.ReactNode }) => {
  const [notificationApi, contextHolder] = notification.useNotification();

  const showNotification: ShowNotificationFunction = (type, message, description) => {
    notificationApi[type]({
      message,
      description,
      placement: 'topRight',
    });
  };

  return (
    <NotificationContext.Provider value={{ showNotification, notificationApi }}>
      {contextHolder}
      {children}
    </NotificationContext.Provider>
  );
};

export const useNotification = () => {
  const context = useContext(NotificationContext);
  if (!context) {
    throw new Error('useNotification must be used within a NotificationProvider');
  }
  return context;
};
