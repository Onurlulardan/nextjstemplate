import axios, { AxiosError, AxiosResponse } from 'axios';
import { signOut } from 'next-auth/react';
import axiosRetry from 'axios-retry';
import { RequestOptions, ShowNotificationFunction } from './types/types';

const axiosInstance = axios.create({
  headers: {
    'Content-Type': 'application/json',
  },
});

// Retry configuration
axiosRetry(axiosInstance, {
  retries: 3,
  retryDelay: axiosRetry.exponentialDelay,
  retryCondition: (error: AxiosError) => {
    if (error.response?.data) {
      return false;
    }
    return (
      axiosRetry.isNetworkOrIdempotentRequestError(error) || (error.response?.status ?? 0) >= 500
    );
  },
});

// Request interceptor
axiosInstance.interceptors.request.use((config) => {
  if (!config.url?.startsWith('/api')) {
    config.url = `/api${config.url}`;
  }
  return config;
});

// Response interceptor
axiosInstance.interceptors.response.use(
  (response: AxiosResponse) => {
    // Success notification for POST, PUT, DELETE requests
    if (
      typeof window !== 'undefined' &&
      ['POST', 'PUT', 'DELETE'].includes(response.config.method?.toUpperCase() || '')
    ) {
      const message =
        response.config.method?.toUpperCase() === 'DELETE'
          ? 'Deletion successful!'
          : 'Process completed successfully';

      const showNotification = window.__showNotification as ShowNotificationFunction;
      showNotification?.('success', message);
    }
    return response.data;
  },
  async (error: AxiosError) => {
    if (error.response?.status === 401) {
      if (typeof window !== 'undefined') {
        await signOut({ callbackUrl: '/auth/login' });
      }
    }

    const errorMessage = (error.response?.data as string) || error.message;

    if (typeof window !== 'undefined') {
      const showNotification = window.__showNotification as ShowNotificationFunction;
      const truncatedMessage =
        errorMessage.length > 500 ? errorMessage.slice(0, 497) + '...' : errorMessage;
      showNotification?.('error', 'Error', truncatedMessage);
    }

    throw new Error(errorMessage);
  }
);

async function apiClient<T = any>(
  endpoint: string,
  method = 'GET',
  data: any = null,
  options: RequestOptions = {}
) {
  const { headers = {}, ...params } = options;

  const response = await axiosInstance({
    url: endpoint,
    method,
    data: method !== 'GET' ? data : null,
    params: method === 'GET' ? data || params : params,
    headers,
  });

  return response as T;
}

// HTTP request methods
export const getRequest = <T = any>(endpoint: string, options: RequestOptions = {}) => {
  return apiClient<T>(endpoint, 'GET', null, options);
};

export const postRequest = <T = any>(endpoint: string, data: any, options: RequestOptions = {}) => {
  return apiClient<T>(endpoint, 'POST', data, options);
};

export const putRequest = <T = any>(endpoint: string, data: any, options: RequestOptions = {}) => {
  return apiClient<T>(endpoint, 'PUT', data, options);
};

export const deleteRequest = <T = any>(endpoint: string, options: RequestOptions = {}) => {
  return apiClient<T>(endpoint, 'DELETE', null, options);
};
