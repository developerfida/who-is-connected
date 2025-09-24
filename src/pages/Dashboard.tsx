import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  Users, 
  Globe, 
  Clock, 
  Ban,
  Eye,
  MoreVertical,
  RefreshCw,
  Wifi,
  WifiOff,
  Search,
  Loader2
} from 'lucide-react';
import { connectionApi, settingsApi, monitoringApi } from '@/lib/api';
import { useAllSocket } from '@/hooks/useSocket';
import { useTheme } from '@/hooks/useTheme';
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
  status: string;
  isBlocked: boolean;
  geoLocation?: GeoLocation;
}

interface SecurityAlert {
  _id: string;
  alertType: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  message: string;
  acknowledged: boolean;
  createdAt: string;
}

interface Stats {
  active: number;
  today: number;
  week: number;
  blocked: number;
  unacknowledgedAlerts: number;
}

const Dashboard: React.FC = () => {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [stats, setStats] = useState<Stats>({
    active: 0,
    today: 0,
    week: 0,
    blocked: 0,
    unacknowledgedAlerts: 0
  });
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [scanMessage, setScanMessage] = useState<string>('');
  
  // Socket.io for real-time updates
  const { isConnected, data: socketData } = useAllSocket();
  const { theme } = useTheme();

  const fetchDashboardData = async (showRefreshLoader = false) => {
    try {
      if (showRefreshLoader) {
        setIsRefreshing(true);
      }
      
      const [connectionsData, alertsData, statsData] = await Promise.all([
        connectionApi.getActive(),
        settingsApi.getAlerts({ limit: 5, acknowledged: false }),
        connectionApi.getStats()
      ]);

      setConnections(connectionsData.connections || []);
      setAlerts(alertsData.alerts || []);
      setStats(statsData.stats || stats);
      setLastUpdated(new Date());
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
      setScanMessage('Failed to refresh data. Please try again.');
      setTimeout(() => setScanMessage(''), 3000);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    
    // Auto-refresh every 30 seconds (fallback for when socket is not connected)
    const interval = setInterval(() => {
      if (!isConnected) {
        fetchDashboardData();
      }
    }, 30000);
    return () => clearInterval(interval);
  }, [isConnected]);

  // Update data from socket
  useEffect(() => {
    if (socketData.connections) {
      setConnections(socketData.connections);
      setLastUpdated(new Date());
    }
    if (socketData.alerts) {
      setAlerts(socketData.alerts);
    }
    if (socketData.monitoring) {
      // Update stats from monitoring data if available
      const monitoringStats = {
        active: socketData.monitoring.activeConnections || stats.active,
        today: stats.today,
        week: stats.week,
        blocked: stats.blocked,
        unacknowledgedAlerts: socketData.alerts?.length || stats.unacknowledgedAlerts
      };
      setStats(monitoringStats);
    }
    // Listen for scan completion events and refresh data
    if (socketData.scanCompleted) {
      console.log('🔍 Scan completed, refreshing dashboard data');
      fetchDashboardData();
      setScanMessage('Scan completed successfully!');
      setTimeout(() => setScanMessage(''), 3000);
      setIsScanning(false);
    }
  }, [socketData]);

  const handleScanConnections = async () => {
    try {
      setIsScanning(true);
      setScanMessage('Scanning for remote connections...');
      
      // Call the scan API endpoint
      await monitoringApi.scanConnections();
      
      // The scan completion will be handled by WebSocket event
      // No need for manual timeout - the socketData.scanCompleted event will handle it
    } catch (error) {
      console.error('Failed to scan connections:', error);
      setScanMessage('Scan failed. Please try again.');
      setTimeout(() => setScanMessage(''), 3000);
      setIsScanning(false);
    }
  };

  const handleTerminateConnection = async (connectionId: string) => {
    try {
      await connectionApi.terminate(connectionId, { force: false, reason: 'Manual termination from dashboard' });
      await fetchDashboardData(); // Refresh data
    } catch (error) {
      console.error('Failed to terminate connection:', error);
    }
  };

  const handleBlockConnection = async (connectionId: string) => {
    try {
      await connectionApi.block(connectionId);
      await fetchDashboardData(); // Refresh data
    } catch (error) {
      console.error('Failed to block connection:', error);
    }
  };

  const handleAcknowledgeAlert = async (alertId: string) => {
    try {
      await settingsApi.acknowledgeAlert(alertId);
      await fetchDashboardData(); // Refresh data
    } catch (error) {
      console.error('Failed to acknowledge alert:', error);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800';
      case 'HIGH': return 'text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-900/20 border-orange-200 dark:border-orange-800';
      case 'MEDIUM': return 'text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800';
      case 'LOW': return 'text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800';
      default: return 'text-gray-600 dark:text-gray-400 bg-gray-50 dark:bg-gray-800 border-gray-200 dark:border-gray-700';
    }
  };

  const getConnectionTypeColor = (type: string) => {
    switch (type) {
      case 'RDP': return 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300';
      case 'SSH': return 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300';
      case 'VNC': return 'bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300';
      case 'TeamViewer': return 'bg-orange-100 dark:bg-orange-900/30 text-orange-800 dark:text-orange-300';
      case 'HTTPS': return 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-800 dark:text-emerald-300';
      case 'HTTP': return 'bg-cyan-100 dark:bg-cyan-900/30 text-cyan-800 dark:text-cyan-300';
      case 'WEB': return 'bg-indigo-100 dark:bg-indigo-900/30 text-indigo-800 dark:text-indigo-300';
      case 'WebSocket': return 'bg-teal-100 dark:bg-teal-900/30 text-teal-800 dark:text-teal-300';
      default: return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300';
    }
  };

  const getDirectionColor = (direction: string) => {
    switch (direction) {
      case 'inbound': return 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300';
      case 'outbound': return 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300';
      case 'local': return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300';
      default: return 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300';
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
      case 'HIGH': return 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300 border-red-200 dark:border-red-800';
      case 'MEDIUM': return 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300 border-yellow-200 dark:border-yellow-800';
      case 'LOW': return 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300 border-green-200 dark:border-green-800';
      default: return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300 border-gray-200 dark:border-gray-700';
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50 dark:bg-gray-900">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto bg-gray-50 dark:bg-gray-900 min-h-screen">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
            <Shield className="w-8 h-8 text-blue-600" />
            Security Dashboard
          </h1>
          <p className="text-gray-600 dark:text-gray-300 mt-1">
            Monitor and manage remote connections to your system
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-sm">
            {isConnected ? (
              <>
                <Wifi className="w-4 h-4 text-green-500" />
                <span className="text-green-600 dark:text-green-400">Live</span>
              </>
            ) : (
              <>
                <WifiOff className="w-4 h-4 text-gray-400" />
                <span className="text-gray-500 dark:text-gray-400">Offline</span>
              </>
            )}
          </div>
          <div className="text-sm text-gray-500 dark:text-gray-400">
            Last updated: {lastUpdated.toLocaleTimeString()}
          </div>
          <div className="flex items-center gap-3">
            {scanMessage && (
              <div className={`text-sm px-3 py-1 rounded-md ${
                scanMessage.includes('failed') || scanMessage.includes('Failed') 
                  ? 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800' 
                  : scanMessage.includes('completed') 
                  ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300 border border-green-200 dark:border-green-800'
                  : 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800'
              }`}>
                {scanMessage}
              </div>
            )}
            <button
              onClick={handleScanConnections}
              disabled={isScanning || isRefreshing}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {isScanning ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Search className="w-4 h-4" />
              )}
              {isScanning ? 'Scanning...' : 'Scan Now'}
            </button>
            <button
              onClick={() => fetchDashboardData(true)}
              disabled={isRefreshing || isScanning}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {isRefreshing ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <RefreshCw className="w-4 h-4" />
              )}
              {isRefreshing ? 'Refreshing...' : 'Refresh'}
            </button>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Active Connections</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.active}</p>
            </div>
            <Activity className="w-8 h-8 text-green-600" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Today's Connections</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.today}</p>
            </div>
            <Clock className="w-8 h-8 text-blue-600" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">This Week</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.week}</p>
            </div>
            <Users className="w-8 h-8 text-purple-600" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Blocked</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.blocked}</p>
            </div>
            <Ban className="w-8 h-8 text-red-600" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Alerts</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.unacknowledgedAlerts}</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-orange-600" />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Active Connections */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white flex items-center gap-2">
              <Globe className="w-5 h-5 text-blue-600" />
              Network Connections
            </h2>
            <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
              Remote access and web browsing activity
            </p>
          </div>
          <div className="p-6">
            {connections.length === 0 ? (
              <div className="text-center py-8">
                <Globe className="w-12 h-12 text-gray-300 mx-auto mb-4" />
                <p className="text-gray-500 dark:text-gray-400">No active remote connections</p>
              </div>
            ) : (
              <div className="space-y-4">
                {connections.map((connection) => (
                  <div key={connection._id} className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-3">
                        <span className={cn(
                          "px-2 py-1 rounded-full text-xs font-medium",
                          getConnectionTypeColor(connection.connectionType)
                        )}>
                          {connection.connectionType}
                        </span>
                        {connection.direction && (
                          <span className={cn(
                            "px-2 py-1 rounded-full text-xs font-medium flex items-center gap-1",
                            getDirectionColor(connection.direction)
                          )}>
                            <span>{getDirectionIcon(connection.direction)}</span>
                            {connection.direction}
                          </span>
                        )}
                        <span className="font-medium text-gray-900 dark:text-white">
                          {connection.domain || `${connection.remoteIP}:${connection.remotePort}`}
                        </span>
                        {connection.isSuspicious && (
                          <span className="px-2 py-1 rounded-full text-xs font-medium bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300 flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" />
                            Suspicious
                          </span>
                        )}
                        {connection.securityRisk && connection.securityRisk !== 'LOW' && (
                          <span className={cn(
                            "px-2 py-1 rounded-full text-xs font-medium",
                            getSecurityRiskColor(connection.securityRisk)
                          )}>
                            {connection.securityRisk} Risk
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleTerminateConnection(connection._id)}
                          className="p-1 text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
                          title="Terminate Connection"
                        >
                          <Ban className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleBlockConnection(connection._id)}
                          className="p-1 text-orange-600 hover:bg-orange-50 dark:hover:bg-orange-900/20 rounded"
                          title="Block IP"
                        >
                          <Shield className="w-4 h-4" />
                        </button>
                        <button className="p-1 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700 rounded">
                          <MoreVertical className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                    <div className="text-sm text-gray-600 dark:text-gray-400 space-y-1">
                      <div className="flex items-center gap-2">
                        <span>Remote: {connection.remoteIP}:{connection.remotePort}</span>
                        {connection.geoLocation && (
                          <div className="flex items-center gap-2">
                            <span className="text-lg">{getCountryFlag(connection.geoLocation.countryCode)}</span>
                            <span className="text-xs text-gray-500 dark:text-gray-400">
                              {formatLocation(connection.geoLocation)}
                            </span>
                            {getCountryRiskLevel(connection.geoLocation.countryCode) !== 'low' && (
                              <span className={cn(
                                "px-1.5 py-0.5 rounded text-xs font-medium",
                                getRiskBgColor(getCountryRiskLevel(connection.geoLocation.countryCode))
                              )}>
                                {getCountryRiskLevel(connection.geoLocation.countryCode)} risk
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                      <div>Local Port: {connection.localPort}</div>
                      <div>Protocol: {connection.protocol}</div>
                      {connection.geoLocation?.isp && (
                        <div>ISP: {formatISP(connection.geoLocation)}</div>
                      )}
                      {connection.domain && (
                        <div>Domain: {connection.domain}</div>
                      )}
                      {connection.browserProcess && (
                        <div>Browser: {connection.browserProcess}</div>
                      )}
                      {connection.processName && (
                        <div>Process: {connection.processName}</div>
                      )}
                      {connection.username && (
                        <div>User: {connection.username}</div>
                      )}
                      <div>Started: {new Date(connection.startTime).toLocaleString()}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Security Alerts */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-orange-600" />
              Security Alerts
            </h2>
          </div>
          <div className="p-6">
            {alerts.length === 0 ? (
              <div className="text-center py-8">
                <AlertTriangle className="w-12 h-12 text-gray-300 mx-auto mb-4" />
                <p className="text-gray-500 dark:text-gray-400">No active security alerts</p>
              </div>
            ) : (
              <div className="space-y-4">
                {alerts.map((alert) => (
                  <div key={alert._id} className={cn(
                    "border rounded-lg p-4",
                    getSeverityColor(alert.severity)
                  )}>
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className={cn(
                          "px-2 py-1 rounded-full text-xs font-medium",
                          getSeverityColor(alert.severity)
                        )}>
                          {alert.severity}
                        </span>
                        <span className="font-medium text-gray-900 dark:text-white">{alert.alertType.replace('_', ' ')}</span>
                      </div>
                      <button
                        onClick={() => handleAcknowledgeAlert(alert._id)}
                        className="text-xs px-2 py-1 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-50 dark:hover:bg-gray-600 text-gray-900 dark:text-white"
                      >
                        Acknowledge
                      </button>
                    </div>
                    <p className="text-sm mb-2 text-gray-900 dark:text-white">{alert.message}</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {new Date(alert.createdAt).toLocaleString()}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;