/**
 * API utilities for making authenticated requests
 */

const API_BASE_URL = 'http://localhost:3001/api';

// Get token from localStorage or auth store
const getAuthToken = (): string | null => {
  const authStorage = localStorage.getItem('auth-storage');
  if (authStorage) {
    try {
      const parsed = JSON.parse(authStorage);
      return parsed.token || null;
    } catch {
      return null;
    }
  }
  return null;
};

// Create authenticated fetch wrapper
const authenticatedFetch = async (url: string, options: RequestInit = {}): Promise<Response> => {
  const token = getAuthToken();
  
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  return fetch(`${API_BASE_URL}${url}`, {
    ...options,
    headers,
  });
};

// API response type
interface ApiResponse<T = any> {
  success: boolean;
  message?: string;
  data?: T;
  error?: string;
}

// Generic API call handler
const apiCall = async <T = any>(url: string, options: RequestInit = {}): Promise<T> => {
  try {
    const response = await authenticatedFetch(url, options);
    const data: ApiResponse<T> = await response.json();

    if (!response.ok) {
      throw new Error(data.message || data.error || `HTTP ${response.status}`);
    }

    return (data.data || data) as T;
  } catch (error) {
    console.error(`API call failed for ${url}:`, error);
    throw error;
  }
};

// Connection API
export const connectionApi = {
  getActive: () => apiCall('/connections/active'),
  getHistory: (params?: {
    page?: number;
    limit?: number;
    startDate?: string;
    endDate?: string;
    ipAddress?: string;
    status?: string;
    connectionType?: string;
    username?: string;
  }) => {
    const searchParams = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          searchParams.append(key, value.toString());
        }
      });
    }
    const queryString = searchParams.toString();
    return apiCall(`/connections/history${queryString ? `?${queryString}` : ''}`);
  },
  getRemoteUserConnections: (username: string, params?: {
    page?: number;
    limit?: number;
    startDate?: string;
    endDate?: string;
    ipAddress?: string;
    status?: string;
    connectionType?: string;
  }) => {
    const searchParams = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          searchParams.append(key, value.toString());
        }
      });
    }
    const queryString = searchParams.toString();
    return apiCall(`/connections/remote-user/${username}${queryString ? `?${queryString}` : ''}`);
  },
  getDetails: (id: string) => apiCall(`/connections/${id}`),
  terminate: (id: string, data: { force?: boolean; reason?: string }) =>
    apiCall(`/connections/${id}/terminate`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  block: (id: string) =>
    apiCall(`/connections/${id}/block`, {
      method: 'POST',
    }),
  getStats: () => apiCall('/connections/stats/overview'),
};

// Settings API
export const settingsApi = {
  // Blocking Rules
  getBlockingRules: () => apiCall('/settings/blocking-rules'),
  createBlockingRule: (data: {
    ipAddress: string;
    port?: number;
    protocol?: 'TCP' | 'UDP' | 'ALL';
    ruleType: 'IP_BLOCK' | 'PORT_BLOCK' | 'GEO_BLOCK';
    enabled?: boolean;
  }) =>
    apiCall('/settings/blocking-rules', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  updateBlockingRule: (id: string, data: any) =>
    apiCall(`/settings/blocking-rules/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),
  deleteBlockingRule: (id: string) =>
    apiCall(`/settings/blocking-rules/${id}`, {
      method: 'DELETE',
    }),

  // Alert Configurations
  getAlertConfigs: () => apiCall('/settings/alert-configs'),
  saveAlertConfig: (data: {
    alertType: string;
    emailEnabled?: boolean;
    desktopEnabled?: boolean;
    thresholds?: Record<string, any>;
  }) =>
    apiCall('/settings/alert-configs', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  deleteAlertConfig: (alertType: string) =>
    apiCall(`/settings/alert-configs/${alertType}`, {
      method: 'DELETE',
    }),

  // Security Alerts
  getAlerts: (params?: {
    page?: number;
    limit?: number;
    severity?: string;
    acknowledged?: boolean;
  }) => {
    const searchParams = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          searchParams.append(key, value.toString());
        }
      });
    }
    const queryString = searchParams.toString();
    return apiCall(`/settings/alerts${queryString ? `?${queryString}` : ''}`);
  },
  acknowledgeAlert: (id: string) =>
    apiCall(`/settings/alerts/${id}/acknowledge`, {
      method: 'POST',
    }),
  acknowledgeAllAlerts: (severity?: string) =>
    apiCall('/settings/alerts/acknowledge-all', {
      method: 'POST',
      body: JSON.stringify({ severity }),
    }),
};

// Monitoring API
export const monitoringApi = {
  getStatus: () => apiCall('/monitoring/status'),
  getServices: () => apiCall('/monitoring/services'),
  getNetwork: (range?: string) => {
    const params = range ? `?range=${range}` : '';
    return apiCall(`/monitoring/network${params}`);
  },
  getResources: (range?: string) => {
    const params = range ? `?range=${range}` : '';
    return apiCall(`/monitoring/resources${params}`);
  },
  getProcesses: () => apiCall('/monitoring/processes'),
  scanConnections: () => apiCall('/monitoring/scan', {
    method: 'POST',
  }),
};

// Auth API (for profile updates, etc.)
export const authApi = {
  getProfile: () => apiCall('/auth/profile'),
  verifyToken: () => apiCall('/auth/verify'),
};

// Export utility functions
export { authenticatedFetch, apiCall };
export default {
  connection: connectionApi,
  settings: settingsApi,
  monitoring: monitoringApi,
  auth: authApi,
};