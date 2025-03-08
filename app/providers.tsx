'use client';

import { App, ConfigProvider, theme } from 'antd';
import { createContext, useContext, useState, useEffect } from 'react';
import baseTheme from '@/config/theme.json';
import { NotificationProvider } from '@/contexts/NotificationContext';
import { useNotificationSetup } from '@/hooks/useNotificationSetup';

interface ThemeContextType {
  isDark: boolean;
  toggleTheme: () => void;
}

export const ThemeContext = createContext<ThemeContextType>({
  isDark: false,
  toggleTheme: () => {},
});

export function useTheme() {
  return useContext(ThemeContext);
}

function NotificationSetup({ children }: { children: React.ReactNode }) {
  useNotificationSetup();
  return <>{children}</>;
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
      setIsDark(savedTheme === 'dark');
    } else {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      setIsDark(prefersDark);
    }
  }, []);

  const toggleTheme = () => {
    const newTheme = !isDark;
    setIsDark(newTheme);
    localStorage.setItem('theme', newTheme ? 'dark' : 'light');
  };

  const themeConfig = {
    ...baseTheme,
    algorithm: isDark ? theme.darkAlgorithm : theme.defaultAlgorithm,
  };

  return (
    <ThemeContext.Provider value={{ isDark, toggleTheme }}>
      <ConfigProvider theme={themeConfig}>
        <App>
          <NotificationProvider>
            <NotificationSetup>{children}</NotificationSetup>
          </NotificationProvider>
        </App>
      </ConfigProvider>
    </ThemeContext.Provider>
  );
}
