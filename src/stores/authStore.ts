import { create } from 'zustand';

export interface User {
  id: string;
  username: string;
  role: 'admin' | 'user';
  createdAt: string;
  lastLogin?: string;
}

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
}

interface AuthActions {
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
  register: (username: string, password: string, role?: 'admin' | 'user') => Promise<boolean>;
  verifyToken: () => Promise<boolean>;
  clearError: () => void;
  setLoading: (loading: boolean) => void;
}

type AuthStore = AuthState & AuthActions;

const API_BASE_URL = 'http://localhost:3001/api';

export const useAuthStore = create<AuthStore>()((set, get) => ({
      // Initial state
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,

      // Actions
      login: async (username: string, password: string) => {
        set({ isLoading: true, error: null });
        
        try {
          const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
          });

          const data = await response.json();

          if (response.ok && data.success) {
            set({
              user: data.user,
              token: data.token,
              isAuthenticated: true,
              isLoading: false,
              error: null,
            });
            return true;
          } else {
            set({
              error: data.message || 'Login failed',
              isLoading: false,
            });
            return false;
          }
        } catch (error) {
          set({
            error: 'Network error. Please check your connection.',
            isLoading: false,
          });
          return false;
        }
      },

      register: async (username: string, password: string, role = 'user' as const) => {
        set({ isLoading: true, error: null });
        
        try {
          const response = await fetch(`${API_BASE_URL}/auth/register`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password, role }),
          });

          const data = await response.json();

          if (response.ok && data.success) {
            set({
              user: data.user,
              token: data.token,
              isAuthenticated: true,
              isLoading: false,
              error: null,
            });
            return true;
          } else {
            set({
              error: data.message || 'Registration failed',
              isLoading: false,
            });
            return false;
          }
        } catch (error) {
          set({
            error: 'Network error. Please check your connection.',
            isLoading: false,
          });
          return false;
        }
      },

      logout: () => {
        const { token } = get();
        
        // Call logout API if token exists
        if (token) {
          fetch(`${API_BASE_URL}/auth/logout`, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json',
            },
          }).catch(() => {
            // Ignore errors on logout
          });
        }

        set({
          user: null,
          token: null,
          isAuthenticated: false,
          error: null,
        });
      },

      verifyToken: async () => {
        const { token } = get();
        
        if (!token) {
          return false;
        }

        set({ isLoading: true });
        
        try {
          const response = await fetch(`${API_BASE_URL}/auth/verify`, {
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json',
            },
          });

          const data = await response.json();

          if (response.ok && data.success) {
            set({
              user: data.user,
              isAuthenticated: true,
              isLoading: false,
              error: null,
            });
            return true;
          } else {
            // Token is invalid, clear auth state
            set({
              user: null,
              token: null,
              isAuthenticated: false,
              isLoading: false,
              error: null,
            });
            return false;
          }
        } catch (error) {
          set({
            error: 'Failed to verify authentication',
            isLoading: false,
          });
          return false;
        }
      },

      clearError: () => {
        set({ error: null });
      },

      setLoading: (loading: boolean) => {
        set({ isLoading: loading });
      },
  }));

// Simple localStorage persistence
const persistAuth = () => {
  const state = useAuthStore.getState();
  localStorage.setItem('auth-storage', JSON.stringify({
    user: state.user,
    token: state.token,
    isAuthenticated: state.isAuthenticated
  }));
};

const loadAuth = () => {
  try {
    const stored = localStorage.getItem('auth-storage');
    if (stored) {
      const data = JSON.parse(stored);
      useAuthStore.setState({
        user: data.user,
        token: data.token,
        isAuthenticated: data.isAuthenticated
      });
    }
  } catch (error) {
    console.error('Failed to load auth state:', error);
  }
};

// Load auth state on initialization
loadAuth();

// Subscribe to changes and persist
useAuthStore.subscribe((state) => {
  localStorage.setItem('auth-storage', JSON.stringify({
    user: state.user,
    token: state.token,
    isAuthenticated: state.isAuthenticated
  }));
});

export { persistAuth, loadAuth };