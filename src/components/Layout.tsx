import React, { useEffect } from 'react';
import { Outlet, Navigate, useLocation, Link } from 'react-router-dom';
import { 
  Shield, 
  LayoutDashboard, 
  History, 
  Settings, 
  Monitor, 
  LogOut, 
  User,
  Menu,
  X,
  UserCheck,
  Clock
} from 'lucide-react';
import { useAuthStore } from '@/stores/authStore';
import { cn } from '@/lib/utils';

const Layout: React.FC = () => {
  const { user, isAuthenticated, logout, verifyToken } = useAuthStore();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = React.useState(false);

  useEffect(() => {
    // Verify token on app load
    if (isAuthenticated) {
      verifyToken();
    }
  }, [isAuthenticated, verifyToken]);

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  const navigation = [
    {
      name: 'Dashboard',
      href: '/',
      icon: LayoutDashboard,
      current: location.pathname === '/'
    },
    {
      name: 'Connection History',
      href: '/history',
      icon: History,
      current: location.pathname === '/history'
    },
    {
      name: 'Recent Connections',
      href: '/recent',
      icon: Clock,
      current: location.pathname === '/recent'
    },
    {
      name: 'Remote User Connections',
      href: '/remote-users',
      icon: UserCheck,
      current: location.pathname === '/remote-users'
    },
    {
      name: 'Security Settings',
      href: '/settings',
      icon: Settings,
      current: location.pathname === '/settings'
    },
    {
      name: 'System Monitor',
      href: '/monitor',
      icon: Monitor,
      current: location.pathname === '/monitor'
    }
  ];

  const handleLogout = () => {
    logout();
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Mobile sidebar backdrop */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        >
          <div className="fixed inset-0 bg-gray-600 bg-opacity-75" />
        </div>
      )}

      {/* Sidebar */}
      <div className={cn(
        "fixed inset-y-0 left-0 z-50 w-64 bg-white shadow-lg transform transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:inset-0",
        sidebarOpen ? "translate-x-0" : "-translate-x-full"
      )}>
        <div className="flex items-center justify-between h-16 px-6 border-b border-gray-200">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-blue-600" />
            <span className="text-xl font-bold text-gray-900">SecureMonitor</span>
          </div>
          <button
            onClick={() => setSidebarOpen(false)}
            className="lg:hidden p-1 rounded-md text-gray-400 hover:text-gray-500"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="mt-6 px-3 pb-24">
          <div className="space-y-1">
            {navigation.map((item) => {
              const Icon = item.icon;
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  onClick={() => setSidebarOpen(false)}
                  className={cn(
                    "flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors",
                    item.current
                      ? "bg-blue-50 text-blue-700 border-r-2 border-blue-700"
                      : "text-gray-700 hover:bg-gray-50 hover:text-gray-900"
                  )}
                >
                  <Icon className="w-5 h-5" />
                  {item.name}
                </Link>
              );
            })}
          </div>
        </nav>

        {/* User info and logout */}
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-gray-200">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
              <User className="w-4 h-4 text-blue-600" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-900 truncate">
                {user?.username}
              </p>
              <p className="text-xs text-gray-500 capitalize">
                {user?.role}
              </p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 w-full px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 rounded-lg transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Sign Out
          </button>
        </div>
      </div>

      {/* Main content */}
      <div className="lg:pl-64">
        {/* Top bar */}
        <div className="sticky top-0 z-10 bg-white shadow-sm border-b border-gray-200 lg:hidden">
          <div className="flex items-center justify-between h-16 px-4">
            <button
              onClick={() => setSidebarOpen(true)}
              className="p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-3">
              <Shield className="w-6 h-6 text-blue-600" />
              <span className="text-lg font-semibold text-gray-900">SecureMonitor</span>
            </div>
            <div className="w-9" /> {/* Spacer for centering */}
          </div>
        </div>

        {/* Page content */}
        <main className="min-h-screen">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default Layout;