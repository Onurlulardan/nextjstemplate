'use client';

import { useEffect } from 'react';
import { useNotification } from '@/contexts/NotificationContext';

export const useNotificationSetup = () => {
  const { showNotification } = useNotification();

  useEffect(() => {
    if (typeof window !== 'undefined') {
      // @ts-ignore
      window.__showNotification = showNotification;
    }

    return () => {
      if (typeof window !== 'undefined') {
        // @ts-ignore
        delete window.__showNotification;
      }
    };
  }, [showNotification]);
};
