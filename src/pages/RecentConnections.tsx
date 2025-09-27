import React, { useState, useEffect } from 'react';
import {
  Clock,
  Search,
  Filter,
  Download,
  Eye,
  Ban,
  Shield,
  Globe,
  AlertTriangle,
  RefreshCw,
  UserCheck
} from 'lucide-react';
import { connectionApi } from '@/lib/api';
import { useAllSocket } from '@/hooks/useSocket';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

import { GeoLocation, getCountryFlag, formatLocation, formatISP, getCountryRiskLevel, getRiskBgColor } from '../utils/geoip';

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
  securityRisk?: string;
  geoLocation?: GeoLocation;
}

const RecentConnections: React.FC = () => {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [filteredConnections, setFilteredConnections] = useState<Connection[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [connectionTypeFilter, setConnectionTypeFilter] = useState<string>('all');
  const [stats, setStats] = useState({ total: 0, active: 0, blocked: 0, byType: {}, byProtocol: {} });
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  // Socket.io for real-time updates
  const { isConnected, data: socketData } = useAllSocket();

  // Calculate 15 minutes ago
  const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();

  const fetchRecentConnections = async () => {
    try {
      setIsLoading(true);
      const response = await connectionApi.getHistory({
        startDate: fifteenMinutesAgo,
        limit: 100 // Get more results to ensure we capture all recent connections
      });

      // Filter connections to only show those from the last 15 minutes
      const recentConnections = (response.connections || []).filter(
        (conn: Connection) => new Date(conn.startTime) >= new Date(fifteenMinutesAgo)
      );

      setConnections(recentConnections);
      
      // Calculate stats for recent connections
      const recentStats = {
        total: recentConnections.length,
        active: recentConnections.filter((c: Connection) => c.status === 'active').length,
        blocked: recentConnections.filter((c: Connection) => c.isBlocked).length,
        byType: {},
        byProtocol: {}
      };
      
      setStats(recentStats);
    } catch (error) {
      console.error('Error fetching recent connections:', error);
      toast.error('Failed to load recent connections');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchRecentConnections();
    // Set up interval to refresh every 30 seconds
    const interval = setInterval(fetchRecentConnections, 30000);
    return () => clearInterval(interval);
  }, []);

  // Update connections from socket
  useEffect(() => {
    if (socketData.connections) {
      // Filter for recent connections only
      const recentConnections = socketData.connections.filter(
        (conn: Connection) => new Date(conn.startTime) >= new Date(fifteenMinutesAgo)
      );
      if (recentConnections.length > 0) {
        setConnections(recentConnections);
        setLastUpdated(new Date());
      }
    }

    // Listen for scan completion events and refresh data
    if (socketData.scanCompleted) {
      console.log('🔍 Scan completed, refreshing recent connections data');
      fetchRecentConnections();
    }
  }, [socketData]);

  // Filter connections based on search and filters
  useEffect(() => {
    let filtered = connections;

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(conn =>
        conn.remoteIP.toLowerCase().includes(searchTerm.toLowerCase()) ||
        conn.connectionType.toLowerCase().includes(searchTerm.toLowerCase()) ||
        conn.processName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        conn.domain?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        conn.username?.toLowerCase().includes(searchTerm.toLowerCase())
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
        reason: 'Terminated from Recent Connections panel'
      });
      await fetchRecentConnections();
    } catch (error) {
      console.error('Failed to terminate connection:', error);
    }
  };

  const handleBlockConnection = async (connectionId: string) => {
    try {
      await connectionApi.block(connectionId);
      await fetchRecentConnections();
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

  const getDirectionColor = (direction?: string) => {
    switch (direction) {
      case 'inbound': return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400';
      case 'outbound': return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400';
      case 'local': return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
      default: return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400';
    }
  };

  const getDirectionIcon = (direction?: string) => {
    switch (direction) {
      case 'inbound': return '↓';
      case 'outbound': return '↑';
      case 'local': return '⟷';
      default: return '?';
    }
  };

  const exportConnections = () => {
    const csvContent = [
      ['Timestamp', 'Remote IP', 'Port', 'Type', 'Status', 'Process', 'Username', 'Domain', 'Direction'].join(','),
      ...filteredConnections.map(conn => [
        new Date(conn.startTime).toLocaleString(),
        conn.remoteIP,
        conn.remotePort,
        conn.connectionType,
        conn.status,
        conn.processName || '',
        conn.username || '',
        conn.domain || '',
        conn.direction || 'unknown'
      ].join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `recent-connections-${new Date().toISOString().split('T')[0]}.csv`;
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
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
            <Clock className="w-8 h-8 text-blue-600" />
            Recent Connections
          </h1>
          <p className="text-gray-600 dark:text-gray-300 mt-1">
            New connections from the last 15 minutes
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-sm text-gray-500 dark:text-gray-400">
            Last updated: {lastUpdated.toLocaleTimeString()}
          </div>
          <button
            onClick={fetchRecentConnections}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Total Recent Connections</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.total}</p>
            </div>
            <Clock className="w-8 h-8 text-blue-600" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Active Connections</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.active}</p>
            </div>
            <Globe className="w-8 h-8 text-green-600" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Blocked Connections</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.blocked}</p>
            </div>
            <Ban className="w-8 h-8 text-red-600" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Suspicious Connections</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {connections.filter(c => c.isSuspicious).length}
              </p>
            </div>
            <AlertTriangle className="w-8 h-8 text-orange-600" />
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 mb-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Search
            </label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search IP, type, process, user..."
                className="w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Status
            </label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="closed">Closed</option>
              <option value="blocked">Blocked</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Connection Type
            </label>
            <select
              value={connectionTypeFilter}
              onChange={(e) => setConnectionTypeFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
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
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Recent Connections ({filteredConnections.length})
          </h2>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            Showing connections from the last 15 minutes
          </p>
        </div>

        {filteredConnections.length === 0 ? (
          <div className="text-center py-12">
            <Clock className="w-12 h-12 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
            <p className="text-gray-500 dark:text-gray-400">No recent connections found</p>
            <p className="text-sm text-gray-400 dark:text-gray-500 mt-1">
              New connections will appear here automatically
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-700">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Connection Details
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Location
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Type & Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Process & User
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Direction
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Timestamp
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                {filteredConnections.map((connection) => (
                  <tr key={connection._id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div>
                        <div className="text-sm font-medium text-gray-900 dark:text-white">
                          {connection.remoteIP}:{connection.remotePort}
                        </div>
                        <div className="text-sm text-gray-500 dark:text-gray-400">
                          Local: {connection.localPort} | {connection.protocol}
                        </div>
                        {connection.domain && (
                          <div className="text-sm text-gray-500 dark:text-gray-400">
                            Domain: {connection.domain}
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {connection.geoLocation ? (
                        <div className="flex items-center gap-2">
                          <span className="text-lg">{getCountryFlag(connection.geoLocation.countryCode)}</span>
                          <div>
                            <div className="text-sm font-medium text-gray-900 dark:text-white">
                              {formatLocation(connection.geoLocation)}
                            </div>
                            {connection.geoLocation.isp && (
                              <div className="text-xs text-gray-500 dark:text-gray-400">
                                {formatISP(connection.geoLocation)}
                              </div>
                            )}
                            {getCountryRiskLevel(connection.geoLocation.countryCode) !== 'low' && (
                              <span className={cn(
                                "inline-flex px-1.5 py-0.5 text-xs font-medium rounded mt-1",
                                getRiskBgColor(getCountryRiskLevel(connection.geoLocation.countryCode))
                              )}>
                                {getCountryRiskLevel(connection.geoLocation.countryCode)} risk
                              </span>
                            )}
                          </div>
                        </div>
                      ) : (
                        <span className="text-sm text-gray-400 dark:text-gray-500">Unknown</span>
                      )}
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
                        <div className="text-sm text-gray-900 dark:text-white">
                          {connection.processName || 'Unknown'}
                        </div>
                        {connection.username && (
                          <div className="text-sm text-gray-500 dark:text-gray-400">
                            User: {connection.username}
                          </div>
                        )}
                        {connection.browserProcess && (
                          <div className="text-sm text-gray-500 dark:text-gray-400">
                            Browser: {connection.browserProcess}
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={cn(
                        "inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium",
                        getDirectionColor(connection.direction)
                      )}>
                        <span>{getDirectionIcon(connection.direction)}</span>
                        {connection.direction || 'unknown'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
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
      </div>
    </div>
  );
};

export default RecentConnections;