import React, { useState, useEffect } from 'react';
import {
  UserCheck,
  Search,
  Filter,
  Download,
  Eye,
  Ban,
  Shield,
  Clock,
  Globe,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw
} from 'lucide-react';
import { connectionApi } from '@/lib/api';
import { useAllSocket } from '@/hooks/useSocket';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

interface Connection {
  _id: string;
  remoteIP: string;
  remotePort: number;
  localPort: string;
  protocol: string;
  connectionType: string;
  processName?: string;
  processId?: number;
  username?: string;
  startTime: string;
  endTime?: string;
  status: string;
  isBlocked: boolean;
  direction?: 'inbound' | 'outbound';
  domain?: string;
  browserProcess?: string;
  isSuspicious?: boolean;
  securityLevel?: 'safe' | 'suspicious' | 'malicious';
}

const RemoteUserConnections: React.FC = () => {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [filteredConnections, setFilteredConnections] = useState<Connection[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [connectionTypeFilter, setConnectionTypeFilter] = useState<string>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [pagination, setPagination] = useState({ page: 1, pages: 1, total: 0, limit: 10 });
  const [stats, setStats] = useState({ total: 0, active: 0, blocked: 0, byType: {}, byProtocol: {} });
  const [recentRemoteConnections, setRecentRemoteConnections] = useState<Connection[]>([]);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  // Socket.io for real-time updates
  const { isConnected, data: socketData } = useAllSocket();

  const itemsPerPage = 10;
  
  // Build filters object
  const filters = {
    ...(statusFilter !== 'all' && { status: statusFilter }),
    ...(connectionTypeFilter !== 'all' && { connectionType: connectionTypeFilter })
  };

  const fetchRemoteUserConnections = async (page = 1) => {
    try {
      setIsLoading(true);
      const response = await connectionApi.getRemoteUserConnections('remote_user', {
        page,
        limit: itemsPerPage,
        ...filters
      });

      setConnections(response.connections || []);
      setPagination(response.pagination || { page: 1, pages: 1, total: 0, limit: itemsPerPage });
      setStats(response.stats || { total: 0, active: 0, blocked: 0, byType: {}, byProtocol: {} });
      
      // Also fetch recent remote connections (last 15 minutes)
      await fetchRecentRemoteConnections();
    } catch (error) {
      console.error('Error fetching remote user connections:', error);
      toast.error('Failed to load remote user connections');
    } finally {
      setIsLoading(false);
    }
  };

  const fetchRecentRemoteConnections = async () => {
    try {
      const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();
      const response = await connectionApi.getRemoteUserConnections('remote_user', {
        startDate: fifteenMinutesAgo,
        status: 'active',
        limit: 50
      });

      // Filter for remote access connections (RDP, SSH, TeamViewer, VNC) from last 15 minutes
      const recentRemoteAccess = (response.connections || []).filter(
        (conn: Connection) => {
          const isRecentConnection = new Date(conn.startTime) >= new Date(fifteenMinutesAgo);
          const isRemoteAccessType = ['RDP', 'SSH', 'TeamViewer', 'VNC'].includes(conn.connectionType);
          const isRemoteUser = conn.username === 'remote_user';
          const isActive = conn.status === 'active';
          return isRecentConnection && isRemoteAccessType && isRemoteUser && isActive;
        }
      );

      setRecentRemoteConnections(recentRemoteAccess);
    } catch (error) {
      console.error('Error fetching recent remote connections:', error);
    }
  };

  useEffect(() => {
    fetchRemoteUserConnections(currentPage);
  }, [currentPage]);

  // Update connections from socket
  useEffect(() => {
    if (socketData.connections) {
      // Filter for remote_user connections only
      const remoteUserConnections = socketData.connections.filter(
        (conn: Connection) => conn.username === 'remote_user'
      );
      if (remoteUserConnections.length > 0) {
        setConnections(remoteUserConnections);
        setLastUpdated(new Date());
        
        // Also update recent remote connections
        const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
        const recentRemoteAccess = remoteUserConnections.filter(
          (conn: Connection) => {
            const isRecentConnection = new Date(conn.startTime) >= fifteenMinutesAgo;
            const isRemoteAccessType = ['RDP', 'SSH', 'TeamViewer', 'VNC'].includes(conn.connectionType);
            const isRemoteUser = conn.username === 'remote_user';
            const isActive = conn.status === 'active';
            return isRecentConnection && isRemoteAccessType && isRemoteUser && isActive;
          }
        );
        setRecentRemoteConnections(recentRemoteAccess);
      }
    }

    if (socketData.alerts) {
      // Handle real-time alerts if needed
    }

    // Listen for scan completion events and refresh data
    if (socketData.scanCompleted) {
      console.log('🔍 Scan completed, refreshing remote user connections data');
      fetchRemoteUserConnections(currentPage);
    }
  }, [socketData, currentPage]);

  // Filter connections based on search and filters
  useEffect(() => {
    let filtered = connections;

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(conn =>
        conn.remoteIP.toLowerCase().includes(searchTerm.toLowerCase()) ||
        conn.connectionType.toLowerCase().includes(searchTerm.toLowerCase()) ||
        conn.processName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        conn.domain?.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // Status filter
    if (statusFilter !== 'all') {
      filtered = filtered.filter(conn => conn.status === statusFilter);
    }

    // Connection type filter
    if (connectionTypeFilter !== 'all') {
      filtered = filtered.filter(conn => conn.connectionType === connectionTypeFilter);
    }

    setFilteredConnections(filtered);
  }, [connections, searchTerm, statusFilter, connectionTypeFilter]);

  const handleTerminateConnection = async (connectionId: string) => {
    try {
      await connectionApi.terminate(connectionId, {
        force: false,
        reason: 'Terminated from Remote User Connections panel'
      });
      await fetchRemoteUserConnections(currentPage);
    } catch (error) {
      console.error('Failed to terminate connection:', error);
    }
  };

  const handleBlockConnection = async (connectionId: string) => {
    try {
      await connectionApi.block(connectionId);
      await fetchRemoteUserConnections(currentPage);
    } catch (error) {
      console.error('Failed to block connection:', error);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-green-600 bg-green-50';
      case 'closed': return 'text-gray-600 bg-gray-50';
      case 'blocked': return 'text-red-600 bg-red-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getConnectionTypeColor = (type: string) => {
    switch (type) {
      case 'RDP': return 'bg-blue-100 text-blue-800';
      case 'SSH': return 'bg-green-100 text-green-800';
      case 'VNC': return 'bg-purple-100 text-purple-800';
      case 'TeamViewer': return 'bg-orange-100 text-orange-800';
      case 'HTTP': return 'bg-cyan-100 text-cyan-800';
      case 'HTTPS': return 'bg-indigo-100 text-indigo-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getSecurityLevelIcon = (level?: string) => {
    switch (level) {
      case 'safe': return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'suspicious': return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
      case 'malicious': return <XCircle className="w-4 h-4 text-red-500" />;
      default: return <Globe className="w-4 h-4 text-gray-400" />;
    }
  };

  const exportConnections = () => {
    const csvContent = [
      ['Timestamp', 'Remote IP', 'Port', 'Type', 'Status', 'Process', 'Domain', 'Security Level'].join(','),
      ...filteredConnections.map(conn => [
        new Date(conn.startTime).toLocaleString(),
        conn.remoteIP,
        conn.remotePort,
        conn.connectionType,
        conn.status,
        conn.processName || '',
        conn.domain || '',
        conn.securityLevel || 'unknown'
      ].join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `remote-user-connections-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-3">
            <UserCheck className="w-8 h-8 text-blue-600" />
            Remote User Connections
          </h1>
          <p className="text-gray-600 mt-1">
            Monitor and manage connections from remote users
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-sm text-gray-500">
            Last updated: {lastUpdated.toLocaleTimeString()}
          </div>
          <button
            onClick={() => fetchRemoteUserConnections(currentPage)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Remote Connections</p>
              <p className="text-2xl font-bold text-gray-900">{stats.total}</p>
            </div>
            <UserCheck className="w-8 h-8 text-blue-600" />
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Connections</p>
              <p className="text-2xl font-bold text-gray-900">
                {stats.active}
              </p>
            </div>
            <Globe className="w-8 h-8 text-green-600" />
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Blocked Connections</p>
              <p className="text-2xl font-bold text-gray-900">
                {stats.blocked}
              </p>
            </div>
            <Ban className="w-8 h-8 text-red-600" />
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Suspicious Connections</p>
              <p className="text-2xl font-bold text-gray-900">
                {connections.filter(c => c.isSuspicious).length}
              </p>
            </div>
            <AlertTriangle className="w-8 h-8 text-orange-600" />
          </div>
        </div>
      </div>

      {/* Recent Remote Access Connections Section */}
      {recentRemoteConnections.length > 0 && (
        <div className="bg-gradient-to-r from-orange-50 to-red-50 rounded-lg shadow-sm border border-orange-200 p-6 mb-8">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                <Clock className="w-5 h-5 text-orange-600" />
                New Remote Access Connections (Last 15 Minutes)
              </h2>
              <p className="text-sm text-gray-600 mt-1">
                Active RDP, SSH, TeamViewer, and VNC connections from user 'remote_user'
              </p>
            </div>
            <div className="text-sm text-orange-700 bg-orange-100 px-3 py-1 rounded-full">
              {recentRemoteConnections.length} active
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {recentRemoteConnections.map((connection) => (
              <div key={connection._id} className="bg-white rounded-lg border border-orange-200 p-4 hover:shadow-md transition-shadow">
                <div className="flex items-center justify-between mb-3">
                  <span className={cn(
                    "inline-flex px-2 py-1 text-xs font-semibold rounded-full",
                    getConnectionTypeColor(connection.connectionType)
                  )}>
                    {connection.connectionType}
                  </span>
                  <div className="flex items-center gap-1">
                    {getSecurityLevelIcon(connection.securityLevel)}
                    {connection.isSuspicious && (
                      <AlertTriangle className="w-4 h-4 text-orange-500" />
                    )}
                  </div>
                </div>
                
                <div className="space-y-2">
                  <div className="text-sm font-medium text-gray-900">
                    {connection.remoteIP}:{connection.remotePort}
                  </div>
                  <div className="text-xs text-gray-500">
                    Local: {connection.localPort} | {connection.protocol}
                  </div>
                  <div className="text-xs text-gray-500">
                    Process: {connection.processName || 'Unknown'}
                  </div>
                  <div className="text-xs text-gray-500">
                    Started: {new Date(connection.startTime).toLocaleTimeString()}
                  </div>
                  {connection.domain && (
                    <div className="text-xs text-gray-500">
                      Domain: {connection.domain}
                    </div>
                  )}
                </div>
                
                <div className="flex items-center gap-2 mt-3 pt-3 border-t border-gray-100">
                  <button
                    onClick={() => handleTerminateConnection(connection._id)}
                    className="flex-1 text-xs px-2 py-1 bg-red-100 text-red-700 rounded hover:bg-red-200 transition-colors"
                    title="Terminate Connection"
                  >
                    Terminate
                  </button>
                  <button
                    onClick={() => handleBlockConnection(connection._id)}
                    className="flex-1 text-xs px-2 py-1 bg-orange-100 text-orange-700 rounded hover:bg-orange-200 transition-colors"
                    title="Block IP"
                  >
                    Block IP
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Search
            </label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search IP, type, process..."
                className="w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Status
            </label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="closed">Closed</option>
              <option value="blocked">Blocked</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Connection Type
            </label>
            <select
              value={connectionTypeFilter}
              onChange={(e) => setConnectionTypeFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All Types</option>
              <option value="RDP">RDP</option>
              <option value="SSH">SSH</option>
              <option value="VNC">VNC</option>
              <option value="TeamViewer">TeamViewer</option>
              <option value="HTTP">HTTP</option>
              <option value="HTTPS">HTTPS</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              onClick={exportConnections}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
            >
              <Download className="w-4 h-4" />
              Export CSV
            </button>
          </div>
        </div>
      </div>

      {/* Connections Table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">
            Remote User Connections ({filteredConnections.length})
          </h2>
        </div>

        {filteredConnections.length === 0 ? (
          <div className="text-center py-12">
            <UserCheck className="w-12 h-12 text-gray-300 mx-auto mb-4" />
            <p className="text-gray-500">No remote user connections found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Connection Details
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Type & Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Process & Domain
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Security
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Timestamp
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredConnections.map((connection) => (
                  <tr key={connection._id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div>
                        <div className="text-sm font-medium text-gray-900">
                          {connection.remoteIP}:{connection.remotePort}
                        </div>
                        <div className="text-sm text-gray-500">
                          Local: {connection.localPort} | {connection.protocol}
                        </div>
                        <div className="text-sm text-gray-500">
                          User: {connection.username}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="space-y-1">
                        <span className={cn(
                          "inline-flex px-2 py-1 text-xs font-semibold rounded-full",
                          getConnectionTypeColor(connection.connectionType)
                        )}>
                          {connection.connectionType}
                        </span>
                        <div>
                          <span className={cn(
                            "inline-flex px-2 py-1 text-xs font-semibold rounded-full",
                            getStatusColor(connection.status)
                          )}>
                            {connection.status}
                          </span>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div>
                        <div className="text-sm text-gray-900">
                          {connection.processName || 'Unknown'}
                        </div>
                        {connection.domain && (
                          <div className="text-sm text-gray-500">
                            {connection.domain}
                          </div>
                        )}
                        {connection.browserProcess && (
                          <div className="text-sm text-gray-500">
                            Browser: {connection.browserProcess}
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        {getSecurityLevelIcon(connection.securityLevel)}
                        <span className="text-sm text-gray-600 capitalize">
                          {connection.securityLevel || 'Unknown'}
                        </span>
                        {connection.isSuspicious && (
                          <AlertTriangle className="w-4 h-4 text-orange-500" />
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      <div>
                        <div>{new Date(connection.startTime).toLocaleDateString()}</div>
                        <div>{new Date(connection.startTime).toLocaleTimeString()}</div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex items-center gap-2">
                        {connection.status === 'active' && (
                          <>
                            <button
                              onClick={() => handleTerminateConnection(connection._id)}
                              className="text-red-600 hover:text-red-700"
                              title="Terminate Connection"
                            >
                              <Ban className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => handleBlockConnection(connection._id)}
                              className="text-orange-600 hover:text-orange-700"
                              title="Block IP"
                            >
                              <Shield className="w-4 h-4" />
                            </button>
                          </>
                        )}
                        <button
                          className="text-blue-600 hover:text-blue-700"
                          title="View Details"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {pagination.pages > 1 && (
          <div className="px-6 py-4 border-t border-gray-200">
            <div className="flex items-center justify-between">
              <div className="text-sm text-gray-700">
                Showing {((currentPage - 1) * itemsPerPage) + 1} to {Math.min(currentPage * itemsPerPage, pagination.total)} of {pagination.total} results
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                  disabled={currentPage === 1}
                  className="px-3 py-1 text-sm border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Previous
                </button>
                <span className="px-3 py-1 text-sm">
                  Page {currentPage} of {pagination.pages}
                </span>
                <button
                  onClick={() => setCurrentPage(prev => Math.min(prev + 1, pagination.pages))}
                  disabled={currentPage === pagination.pages}
                  className="px-3 py-1 text-sm border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default RemoteUserConnections;