import React, { useState, useEffect } from 'react';
import { 
  History, 
  Search, 
  Filter, 
  Download, 
  Eye, 
  Ban, 
  Calendar,
  Globe,
  Clock,
  User,
  ChevronLeft,
  ChevronRight,
  AlertTriangle
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { connectionApi } from '@/lib/api';
import { cn } from '@/lib/utils';

import { GeoLocation, getCountryFlag, formatLocation, formatISP, getCountryRiskLevel, getRiskBgColor } from '../utils/geoip';

interface Connection {
  _id: string;
  remoteIP: string;
  remotePort: number;
  localPort: string;
  protocol: string;
  connectionType: string;
  direction?: string;
  domain?: string;
  browserProcess?: string;
  isSuspicious?: boolean;
  securityRisk?: string;
  processName?: string;
  username?: string;
  startTime: string;
  endTime?: string;
  status: string;
  isBlocked: boolean;
  geoLocation?: GeoLocation;
  createdAt: string;
}

interface Filters {
  ipAddress: string;
  connectionType: string;
  direction: string;
  status: string;
  startDate: string;
  endDate: string;
  country: string;
  processName: string;
}

const ConnectionHistory: React.FC = () => {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [filters, setFilters] = useState<Filters>({
    ipAddress: '',
    connectionType: '',
    direction: '',
    status: '',
    startDate: '',
    endDate: '',
    country: '',
    processName: ''
  });
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 20,
    total: 0,
    pages: 0
  });
  const [showFilters, setShowFilters] = useState(false);

  const fetchConnections = async (page = 1) => {
    setIsLoading(true);
    try {
      const params: any = {
        page,
        limit: pagination.limit
      };

      // Add filters if they have values
      if (filters.ipAddress) params.ipAddress = filters.ipAddress;
      if (filters.connectionType) params.connectionType = filters.connectionType;
      if (filters.direction) params.direction = filters.direction;
      if (filters.status) params.status = filters.status;
      if (filters.startDate) params.startDate = filters.startDate;
      if (filters.endDate) params.endDate = filters.endDate;
      if (filters.country) params.country = filters.country;
      if (filters.processName) params.processName = filters.processName;

      const data = await connectionApi.getHistory(params);
      setConnections(data.connections || []);
      setPagination(data.pagination || pagination);
    } catch (error) {
      console.error('Failed to fetch connection history:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchConnections();
  }, []);

  const handleFilterChange = (key: keyof Filters, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const applyFilters = () => {
    setPagination(prev => ({ ...prev, page: 1 }));
    fetchConnections(1);
  };

  const clearFilters = () => {
    setFilters({
      ipAddress: '',
      connectionType: '',
      direction: '',
      status: '',
      startDate: '',
      endDate: '',
      country: '',
      processName: ''
    });
    setPagination(prev => ({ ...prev, page: 1 }));
    fetchConnections(1);
  };

  const handlePageChange = (newPage: number) => {
    setPagination(prev => ({ ...prev, page: newPage }));
    fetchConnections(newPage);
  };

  const exportData = () => {
    // Create CSV content
    const headers = ['IP Address', 'Port', 'Process', 'Type', 'Protocol', 'Status', 'Start Time', 'End Time', 'Duration'];
    const csvContent = [
      headers.join(','),
      ...connections.map(conn => [
        conn.remoteIP,
        conn.remotePort,
        conn.processName || 'Unknown',
        conn.connectionType,
        conn.protocol,
        conn.status,
        new Date(conn.startTime).toLocaleString(),
        conn.endTime ? new Date(conn.endTime).toLocaleString() : 'Active',
        conn.endTime 
          ? Math.round((new Date(conn.endTime).getTime() - new Date(conn.startTime).getTime()) / 1000 / 60) + ' min'
          : 'Ongoing'
      ].join(','))
    ].join('\n');

    // Download CSV
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `connection-history-${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  };

  const getStatusColor = (status: string, isBlocked: boolean) => {
    if (isBlocked) return 'bg-red-100 text-red-800';
    switch (status) {
      case 'active': return 'bg-green-100 text-green-800';
      case 'closed': return 'bg-gray-100 text-gray-800';
      case 'blocked': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getConnectionTypeColor = (type: string) => {
    switch (type) {
      case 'RDP': return 'bg-blue-100 text-blue-800';
      case 'SSH': return 'bg-green-100 text-green-800';
      case 'VNC': return 'bg-purple-100 text-purple-800';
      case 'TeamViewer': return 'bg-orange-100 text-orange-800';
      case 'HTTPS': return 'bg-emerald-100 text-emerald-800';
      case 'HTTP': return 'bg-cyan-100 text-cyan-800';
      case 'WEB': return 'bg-indigo-100 text-indigo-800';
      case 'WebSocket': return 'bg-teal-100 text-teal-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getDirectionColor = (direction: string) => {
    switch (direction) {
      case 'inbound': return 'bg-red-100 text-red-800';
      case 'outbound': return 'bg-blue-100 text-blue-800';
      case 'local': return 'bg-gray-100 text-gray-800';
      default: return 'bg-yellow-100 text-yellow-800';
    }
  };

  const getDirectionIcon = (direction: string) => {
    switch (direction) {
      case 'inbound': return '↓';
      case 'outbound': return '↑';
      case 'local': return '⟷';
      default: return '?';
    }
  };

  const getSecurityRiskColor = (risk: string) => {
    switch (risk) {
      case 'HIGH': return 'bg-red-100 text-red-800 border-red-200';
      case 'MEDIUM': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'LOW': return 'bg-green-100 text-green-800 border-green-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const calculateDuration = (startTime: string, endTime?: string) => {
    const start = new Date(startTime);
    const end = endTime ? new Date(endTime) : new Date();
    const diffMs = end.getTime() - start.getTime();
    const diffMins = Math.round(diffMs / 1000 / 60);
    
    if (diffMins < 60) return `${diffMins}m`;
    const hours = Math.floor(diffMins / 60);
    const mins = diffMins % 60;
    return `${hours}h ${mins}m`;
  };

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
            <History className="w-8 h-8 text-blue-600" />
            Connection History
          </h1>
          <p className="text-gray-600 dark:text-gray-300 mt-1">
            View and analyze remote access and web browsing activity
          </p>
        </div>
        <div className="flex items-center gap-4">
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={cn(
              "flex items-center gap-2 px-4 py-2 rounded-lg border transition-colors",
              showFilters 
                ? "bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-700 text-blue-700 dark:text-blue-300"
                : "bg-white dark:bg-gray-800 border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
            )}
          >
            <Filter className="w-4 h-4" />
            Filters
          </button>
          <button
            onClick={exportData}
            className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
          >
            <Download className="w-4 h-4" />
            Export CSV
          </button>
        </div>
      </div>

      {/* Filters */}
      {showFilters && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 mb-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-7 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                IP Address
              </label>
              <input
                type="text"
                value={filters.ipAddress}
                onChange={(e) => handleFilterChange('ipAddress', e.target.value)}
                placeholder="192.168.1.100"
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Process Name
              </label>
              <input
                type="text"
                value={filters.processName}
                onChange={(e) => handleFilterChange('processName', e.target.value)}
                placeholder="chrome.exe, svchost.exe"
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Connection Type
              </label>
              <select
                value={filters.connectionType}
                onChange={(e) => handleFilterChange('connectionType', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">All Types</option>
                <option value="RDP">RDP</option>
                <option value="SSH">SSH</option>
                <option value="VNC">VNC</option>
                <option value="TeamViewer">TeamViewer</option>
                <option value="HTTPS">HTTPS</option>
                <option value="HTTP">HTTP</option>
                <option value="WEB">Web</option>
                <option value="WebSocket">WebSocket</option>
                <option value="Other">Other</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Direction
              </label>
              <select
                value={filters.direction}
                onChange={(e) => handleFilterChange('direction', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">All Directions</option>
                <option value="inbound">Inbound</option>
                <option value="outbound">Outbound</option>
                <option value="local">Local</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Status
              </label>
              <select
                value={filters.status}
                onChange={(e) => handleFilterChange('status', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">All Status</option>
                <option value="active">Active</option>
                <option value="closed">Closed</option>
                <option value="blocked">Blocked</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Country
              </label>
              <select
                value={filters.country}
                onChange={(e) => handleFilterChange('country', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">All Countries</option>
                <option value="US">🇺🇸 United States</option>
                <option value="CN">🇨🇳 China</option>
                <option value="RU">🇷🇺 Russia</option>
                <option value="DE">🇩🇪 Germany</option>
                <option value="GB">🇬🇧 United Kingdom</option>
                <option value="FR">🇫🇷 France</option>
                <option value="JP">🇯🇵 Japan</option>
                <option value="IN">🇮🇳 India</option>
                <option value="BR">🇧🇷 Brazil</option>
                <option value="CA">🇨🇦 Canada</option>
                <option value="AU">🇦🇺 Australia</option>
                <option value="KR">🇰🇷 South Korea</option>
                <option value="NL">🇳🇱 Netherlands</option>
                <option value="IT">🇮🇹 Italy</option>
                <option value="ES">🇪🇸 Spain</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Start Date
              </label>
              <input
                type="date"
                value={filters.startDate}
                onChange={(e) => handleFilterChange('startDate', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                End Date
              </label>
              <input
                type="date"
                value={filters.endDate}
                onChange={(e) => handleFilterChange('endDate', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>
          <div className="flex items-center gap-4 mt-4">
            <button
              onClick={applyFilters}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              Apply Filters
            </button>
            <button
              onClick={clearFilters}
              className="px-4 py-2 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
            >
              Clear All
            </button>
          </div>
        </div>
      )}

      {/* Connections Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Connection Records ({pagination.total} total)
          </h2>
        </div>
        
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          </div>
        ) : connections.length === 0 ? (
          <div className="text-center py-12">
            <History className="w-12 h-12 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
            <p className="text-gray-500 dark:text-gray-400">No connection records found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-700">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Connection
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Process
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Location
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Type & Protocol
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Duration
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Time
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                {connections.map((connection) => (
                  <tr key={connection._id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center gap-3">
                        <Globe className="w-4 h-4 text-gray-400" />
                        <div>
                          <div className="font-medium text-gray-900 dark:text-white flex items-center gap-2">
                            <span>{connection.domain || `${connection.remoteIP}:${connection.remotePort}`}</span>
                            {connection.isSuspicious && (
                               <AlertTriangle className="w-4 h-4 text-red-500" />
                             )}
                          </div>
                          <div className="text-sm text-gray-500 dark:text-gray-400">
                            {connection.domain ? `${connection.remoteIP}:${connection.remotePort}` : `Local: ${connection.localPort}`}
                          </div>
                          {connection.browserProcess && (
                            <div className="text-sm text-gray-500 dark:text-gray-400 flex items-center gap-1">
                              <Globe className="w-3 h-3" />
                              {connection.browserProcess}
                            </div>
                          )}
                          {connection.username && (
                            <div className="text-sm text-gray-500 dark:text-gray-400 flex items-center gap-1">
                              <User className="w-3 h-3" />
                              {connection.username}
                            </div>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-900 dark:text-white font-medium">
                        {connection.processName || '-'}
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
                        <div className="flex items-center gap-2">
                          <span className={cn(
                            "inline-flex px-2 py-1 text-xs font-medium rounded-full",
                            getConnectionTypeColor(connection.connectionType)
                          )}>
                            {connection.connectionType}
                          </span>
                          {connection.direction && (
                            <span className={cn(
                              "inline-flex px-2 py-1 text-xs font-medium rounded-full items-center gap-1",
                              getDirectionColor(connection.direction)
                            )}>
                              <span>{getDirectionIcon(connection.direction)}</span>
                              {connection.direction}
                           </span>
                         )}
                         {connection.securityRisk && connection.securityRisk !== 'LOW' && (
                           <span className={cn(
                             "inline-flex px-2 py-1 text-xs font-medium rounded-full",
                             getSecurityRiskColor(connection.securityRisk)
                           )}>
                             {connection.securityRisk}
                           </span>
                         )}
                       </div>
                        <div className="text-sm text-gray-500 dark:text-gray-400">{connection.protocol}</div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={cn(
                        "inline-flex px-2 py-1 text-xs font-medium rounded-full",
                        getStatusColor(connection.status, connection.isBlocked)
                      )}>
                        {connection.isBlocked ? 'Blocked' : connection.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                      {calculateDuration(connection.startTime, connection.endTime)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-900 dark:text-white">
                        {new Date(connection.startTime).toLocaleDateString()}
                      </div>
                      <div className="text-sm text-gray-500 dark:text-gray-400">
                        {new Date(connection.startTime).toLocaleTimeString()}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <Link
                        to={`/connection/${connection._id}`}
                        className="inline-flex items-center gap-1 px-3 py-1 text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-md transition-colors"
                      >
                        <Eye className="w-4 h-4" />
                        Details
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {pagination.pages > 1 && (
          <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <div className="text-sm text-gray-700 dark:text-gray-300">
              Showing {((pagination.page - 1) * pagination.limit) + 1} to {Math.min(pagination.page * pagination.limit, pagination.total)} of {pagination.total} results
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handlePageChange(pagination.page - 1)}
                disabled={pagination.page === 1}
                className="p-2 text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="px-3 py-1 text-sm text-gray-700 dark:text-gray-300">
                Page {pagination.page} of {pagination.pages}
              </span>
              <button
                onClick={() => handlePageChange(pagination.page + 1)}
                disabled={pagination.page === pagination.pages}
                className="p-2 text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ConnectionHistory;