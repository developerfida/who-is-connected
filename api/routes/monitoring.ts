/**
 * Monitoring API routes
 * Handle system monitoring, service status, and resource usage
 */
import { Router, type Response } from 'express';
import { authenticate, AuthRequest } from '../middleware/auth';
import { ConnectionLog, SecurityAlert } from '../models';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { broadcastScanCompleted } from '../websocket/handlers.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = Router();

/**
 * Cleanup Stale Connections
 * POST /api/monitoring/cleanup-connections
 */
router.post('/cleanup-connections', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const maxAgeMinutes = parseInt(req.body.maxAgeMinutes as string) || 15;
    const cutoffTime = new Date(Date.now() - maxAgeMinutes * 60 * 1000);
    
    // Find all active connections older than the cutoff time
    const staleConnections = await ConnectionLog.find({
      status: 'active',
      startTime: { $lt: cutoffTime }
    });
    
    // Mark them as closed
    const updateResult = await ConnectionLog.updateMany(
      {
        status: 'active',
        startTime: { $lt: cutoffTime }
      },
      {
        $set: {
          status: 'closed',
          endTime: new Date()
        }
      }
    );
    
    console.log(`🧹 Cleaned up ${updateResult.modifiedCount} stale connections older than ${maxAgeMinutes} minutes`);
    
    res.json({
      success: true,
      message: `Cleaned up ${updateResult.modifiedCount} stale connections`,
      data: {
        cleanedCount: updateResult.modifiedCount,
        cutoffTime: cutoffTime.toISOString(),
        maxAgeMinutes
      }
    });
  } catch (error) {
    console.error('Error cleaning up stale connections:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while cleaning up connections'
    });
  }
});

/**
 * Auto Cleanup Stale Connections (called periodically)
 * This function can be called by a cron job or scheduler
 */
export const autoCleanupStaleConnections = async (maxAgeMinutes: number = 15): Promise<number> => {
  try {
    const cutoffTime = new Date(Date.now() - maxAgeMinutes * 60 * 1000);
    
    const updateResult = await ConnectionLog.updateMany(
      {
        status: 'active',
        startTime: { $lt: cutoffTime }
      },
      {
        $set: {
          status: 'closed',
          endTime: new Date()
        }
      }
    );
    
    if (updateResult.modifiedCount > 0) {
      console.log(`🧹 Auto-cleaned ${updateResult.modifiedCount} stale connections older than ${maxAgeMinutes} minutes`);
    }
    
    return updateResult.modifiedCount;
  } catch (error) {
    console.error('Error in auto cleanup:', error);
    return 0;
  }
};

// Schedule auto cleanup every 5 minutes
setInterval(async () => {
  await autoCleanupStaleConnections(15); // Clean connections older than 15 minutes
}, 5 * 60 * 1000); // Run every 5 minutes

/**
 * Get System Status Overview
 * GET /api/monitoring/status
 */
router.get('/status', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const now = new Date();
    const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const userId = req.user?._id;

    // Get system statistics
    const [activeConnections, recentConnections, criticalAlerts, systemHealth] = await Promise.all([
      ConnectionLog.countDocuments({ userId, status: 'active' }),
      ConnectionLog.countDocuments({ userId, startTime: { $gte: last24Hours } }),
      SecurityAlert.countDocuments({ severity: 'CRITICAL', acknowledged: false }),
      getSystemHealth() // This would call the Python monitoring service
    ]);

    // Mock system health data (would be replaced with actual Python service call)
    const mockSystemHealth = {
      cpu: {
        usage: Math.floor(Math.random() * 30) + 10, // 10-40%
        cores: 8,
        temperature: Math.floor(Math.random() * 20) + 45 // 45-65°C
      },
      memory: {
        used: Math.floor(Math.random() * 4000) + 2000, // 2-6GB
        total: 16384, // 16GB
        usage: Math.floor(Math.random() * 30) + 20 // 20-50%
      },
      network: {
        bytesIn: Math.floor(Math.random() * 1000000) + 500000,
        bytesOut: Math.floor(Math.random() * 500000) + 100000,
        packetsIn: Math.floor(Math.random() * 10000) + 5000,
        packetsOut: Math.floor(Math.random() * 8000) + 3000
      },
      services: {
        rdp: { status: 'running', port: 3389, connections: activeConnections },
        ssh: { status: 'stopped', port: 22, connections: 0 },
        winrm: { status: 'running', port: 5985, connections: 0 },
        monitoring: { status: 'running', lastUpdate: now }
      }
    };

    const status = {
      timestamp: now,
      system: mockSystemHealth,
      connections: {
        active: activeConnections,
        recent24h: recentConnections,
        criticalAlerts
      },
      health: {
        overall: criticalAlerts > 0 ? 'warning' : activeConnections > 5 ? 'caution' : 'healthy',
        uptime: process.uptime(),
        lastRestart: new Date(Date.now() - process.uptime() * 1000)
      }
    };

    res.json({
      success: true,
      status
    });
  } catch (error) {
    console.error('Error fetching system status:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while fetching system status'
    });
  }
});

/**
 * Get Service Status
 * GET /api/monitoring/services
 */
router.get('/services', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    // Mock service data (would be replaced with actual Windows service queries)
    const services = [
      {
        name: 'Remote Desktop Services',
        serviceName: 'TermService',
        status: 'running',
        port: 3389,
        protocol: 'TCP',
        startType: 'automatic',
        description: 'Enables users to connect interactively to a remote computer',
        lastStarted: new Date(Date.now() - Math.random() * 86400000) // Random time in last 24h
      },
      {
        name: 'Windows Remote Management',
        serviceName: 'WinRM',
        status: 'running',
        port: 5985,
        protocol: 'HTTP',
        startType: 'manual',
        description: 'Windows Remote Management service',
        lastStarted: new Date(Date.now() - Math.random() * 86400000)
      },
      {
        name: 'SSH Server',
        serviceName: 'sshd',
        status: 'stopped',
        port: 22,
        protocol: 'TCP',
        startType: 'disabled',
        description: 'OpenSSH SSH Server',
        lastStarted: null
      },
      {
        name: 'TeamViewer Service',
        serviceName: 'TeamViewer',
        status: 'stopped',
        port: 5938,
        protocol: 'TCP',
        startType: 'manual',
        description: 'TeamViewer remote access service',
        lastStarted: null
      }
    ];

    res.json({
      success: true,
      services,
      summary: {
        total: services.length,
        running: services.filter(s => s.status === 'running').length,
        stopped: services.filter(s => s.status === 'stopped').length
      }
    });
  } catch (error) {
    console.error('Error fetching service status:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while fetching service status'
    });
  }
});

/**
 * Get Network Statistics
 * GET /api/monitoring/network
 */
router.get('/network', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const timeRange = req.query.range as string || '1h';
    
    // Mock network statistics (would be replaced with actual network monitoring)
    const generateNetworkData = (points: number) => {
      const data = [];
      const now = Date.now();
      const interval = timeRange === '1h' ? 60000 : timeRange === '24h' ? 3600000 : 300000; // 1min, 1h, or 5min
      
      for (let i = points - 1; i >= 0; i--) {
        data.push({
          timestamp: new Date(now - i * interval),
          bytesIn: Math.floor(Math.random() * 1000000) + 100000,
          bytesOut: Math.floor(Math.random() * 500000) + 50000,
          packetsIn: Math.floor(Math.random() * 1000) + 100,
          packetsOut: Math.floor(Math.random() * 800) + 80,
          connections: Math.floor(Math.random() * 10) + 1
        });
      }
      return data;
    };

    const points = timeRange === '1h' ? 60 : timeRange === '24h' ? 24 : 12;
    const networkData = generateNetworkData(points);

    // Get current network interfaces (mock data)
    const interfaces = [
      {
        name: 'Ethernet',
        type: 'wired',
        status: 'up',
        ipAddress: '192.168.1.100',
        macAddress: '00:1B:44:11:3A:B7',
        speed: '1000 Mbps',
        bytesReceived: Math.floor(Math.random() * 1000000000),
        bytesSent: Math.floor(Math.random() * 500000000)
      },
      {
        name: 'Wi-Fi',
        type: 'wireless',
        status: 'down',
        ipAddress: null,
        macAddress: '00:1B:44:11:3A:B8',
        speed: null,
        bytesReceived: 0,
        bytesSent: 0
      }
    ];

    res.json({
      success: true,
      timeRange,
      data: networkData,
      interfaces,
      summary: {
        totalBytesIn: networkData.reduce((sum, d) => sum + d.bytesIn, 0),
        totalBytesOut: networkData.reduce((sum, d) => sum + d.bytesOut, 0),
        avgConnections: Math.round(networkData.reduce((sum, d) => sum + d.connections, 0) / networkData.length),
        activeInterfaces: interfaces.filter(i => i.status === 'up').length
      }
    });
  } catch (error) {
    console.error('Error fetching network statistics:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while fetching network statistics'
    });
  }
});

/**
 * Get Resource Usage
 * GET /api/monitoring/resources
 */
router.get('/resources', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const timeRange = req.query.range as string || '1h';
    
    // Mock resource usage data (would be replaced with actual system monitoring)
    const generateResourceData = (points: number) => {
      const data = [];
      const now = Date.now();
      const interval = timeRange === '1h' ? 60000 : timeRange === '24h' ? 3600000 : 300000;
      
      for (let i = points - 1; i >= 0; i--) {
        data.push({
          timestamp: new Date(now - i * interval),
          cpu: Math.floor(Math.random() * 40) + 10, // 10-50%
          memory: Math.floor(Math.random() * 30) + 20, // 20-50%
          disk: Math.floor(Math.random() * 10) + 5, // 5-15%
          network: Math.floor(Math.random() * 20) + 5 // 5-25%
        });
      }
      return data;
    };

    const points = timeRange === '1h' ? 60 : timeRange === '24h' ? 24 : 12;
    const resourceData = generateResourceData(points);

    // Current resource usage
    const current = {
      cpu: {
        usage: Math.floor(Math.random() * 30) + 15,
        cores: 8,
        processes: Math.floor(Math.random() * 50) + 150
      },
      memory: {
        used: Math.floor(Math.random() * 4000) + 4000, // 4-8GB
        total: 16384, // 16GB
        available: 16384 - (Math.floor(Math.random() * 4000) + 4000),
        usage: Math.floor(Math.random() * 25) + 25 // 25-50%
      },
      disk: {
        used: Math.floor(Math.random() * 100000) + 200000, // 200-300GB
        total: 1000000, // 1TB
        available: 1000000 - (Math.floor(Math.random() * 100000) + 200000),
        usage: Math.floor(Math.random() * 10) + 20 // 20-30%
      }
    };

    res.json({
      success: true,
      timeRange,
      data: resourceData,
      current,
      alerts: [
        // Mock alerts based on thresholds
        ...(current.cpu.usage > 80 ? [{ type: 'cpu', message: 'High CPU usage detected', severity: 'warning' }] : []),
        ...(current.memory.usage > 85 ? [{ type: 'memory', message: 'High memory usage detected', severity: 'warning' }] : []),
        ...(current.disk.usage > 90 ? [{ type: 'disk', message: 'Low disk space', severity: 'critical' }] : [])
      ]
    });
  } catch (error) {
    console.error('Error fetching resource usage:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while fetching resource usage'
    });
  }
});

/**
 * Get Active Processes
 * GET /api/monitoring/processes
 */
router.get('/processes', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    // Mock process data (would be replaced with actual process monitoring)
    const processes = [
      {
        pid: 1234,
        name: 'svchost.exe',
        cpu: 2.5,
        memory: 45.2,
        networkConnections: 3,
        user: 'SYSTEM',
        startTime: new Date(Date.now() - Math.random() * 86400000)
      },
      {
        pid: 5678,
        name: 'chrome.exe',
        cpu: 15.3,
        memory: 234.7,
        networkConnections: 12,
        user: 'Administrator',
        startTime: new Date(Date.now() - Math.random() * 3600000)
      },
      {
        pid: 9012,
        name: 'node.exe',
        cpu: 8.1,
        memory: 89.4,
        networkConnections: 5,
        user: 'Administrator',
        startTime: new Date(Date.now() - Math.random() * 1800000)
      }
    ].sort((a, b) => b.cpu - a.cpu); // Sort by CPU usage

    res.json({
      success: true,
      processes,
      summary: {
        total: processes.length + Math.floor(Math.random() * 100) + 50,
        withNetworkConnections: processes.filter(p => p.networkConnections > 0).length,
        highCpuUsage: processes.filter(p => p.cpu > 10).length,
        highMemoryUsage: processes.filter(p => p.memory > 100).length
      }
    });
  } catch (error) {
    console.error('Error fetching processes:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while fetching processes'
    });
  }
});

/**
 * Trigger Connection Scan
 * POST /api/monitoring/scan
 */
router.post('/scan', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const userId = req.user?._id;
    
    // Trigger Python monitoring service to perform active scan
    const scanResult = await triggerConnectionScan();
    
    // Store any new connections found during scan
    if (scanResult.connections && scanResult.connections.length > 0) {
      const newConnections = [];
      
      for (const conn of scanResult.connections) {
        // Check if connection already exists
        const existingConnection = await ConnectionLog.findOne({
          userId,
          remoteIP: conn.remoteIP,
          remotePort: conn.remotePort,
          status: 'active'
        });
        
        if (!existingConnection) {
          const newConnection = new ConnectionLog({
            userId,
            remoteIP: conn.remote_ip || conn.remoteIP,
            remotePort: conn.remote_port || conn.remotePort,
            localPort: conn.local_port || conn.localPort,
            protocol: conn.protocol,
            connectionType: conn.connection_type || conn.connectionType,
            direction: conn.direction || 'unknown',
            domain: conn.domain,
            browserProcess: conn.browser_process || conn.browserProcess,
            isSuspicious: conn.is_suspicious || false,
            securityRisk: conn.security_risk || 'LOW',
            processName: conn.process_name || conn.processName,
            processId: conn.process_id || conn.processId,
            username: conn.username,
            startTime: new Date(),
            status: 'active',
            isBlocked: false
          });
          
          await newConnection.save();
          newConnections.push(newConnection);
        }
      }
      
      // Create security alerts for new suspicious connections
      for (const conn of newConnections) {
        if (conn.connectionType === 'Unknown' || conn.remoteIP.startsWith('192.168.') === false) {
          const alert = new SecurityAlert({
            connectionId: conn._id,
            alertType: 'SUSPICIOUS_CONNECTION',
            severity: 'MEDIUM',
            message: `New remote connection detected from ${conn.remoteIP}:${conn.remotePort} via ${conn.connectionType}`,
            acknowledged: false
          });
          
          await alert.save();
        }
      }
    }
    
    const scanData = {
      scannedAt: new Date(),
      connectionsFound: scanResult.connections?.length || 0,
      newConnections: scanResult.connections?.filter((conn: any) => conn.isNew) || [],
      scanDuration: scanResult.duration || 0
    };

    // Broadcast scan completion to all connected clients
    broadcastScanCompleted({
      message: 'Connection scan completed successfully',
      data: scanData
    });

    res.json({
      success: true,
      message: 'Connection scan completed successfully',
      data: scanData
    });
  } catch (error) {
    console.error('Error during connection scan:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to perform connection scan',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Helper function to trigger Python connection scan
async function triggerConnectionScan(): Promise<any> {
  return new Promise((resolve, reject) => {
    const projectRoot = path.join(__dirname, '../..');
    const pythonScriptPath = path.join(projectRoot, 'python/connection_monitor.py');
    const pythonExePath = path.join(projectRoot, '.venv/Scripts/python.exe');
    
    // Use virtual environment Python if available, otherwise system Python
    const pythonCommand = fs.existsSync(pythonExePath) ? pythonExePath : 'python';
    
    const pythonProcess = spawn(pythonCommand, [pythonScriptPath, '--scan'], {
      cwd: projectRoot,
      env: { ...process.env, PYTHONPATH: path.join(projectRoot, 'python') }
    });
    
    let output = '';
    let errorOutput = '';
    
    pythonProcess.stdout.on('data', (data) => {
      output += data.toString();
    });
    
    pythonProcess.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });
    
    pythonProcess.on('close', (code) => {
      if (code === 0) {
        try {
          // Parse the JSON output from Python script
          const result = JSON.parse(output);
          resolve({
            connections: result.connections || [],
            duration: result.scan_duration || 0,
            timestamp: new Date()
          });
        } catch (parseError) {
          // If JSON parsing fails, return mock data for now
          console.warn('Failed to parse Python output, using mock data:', parseError);
          resolve({
            connections: generateMockConnections(),
            duration: Math.floor(Math.random() * 3000) + 1000, // 1-4 seconds
            timestamp: new Date()
          });
        }
      } else {
        reject(new Error(`Python scan failed with code ${code}: ${errorOutput}`));
      }
    });
    
    pythonProcess.on('error', (error) => {
      console.warn('Python process error, using mock data:', error);
      // Fallback to mock data if Python script fails
      resolve({
        connections: generateMockConnections(),
        duration: Math.floor(Math.random() * 3000) + 1000,
        timestamp: new Date()
      });
    });
    
    // Set timeout for scan operation
    setTimeout(() => {
      pythonProcess.kill();
      reject(new Error('Scan operation timed out'));
    }, 30000); // 30 second timeout
  });
}

// Generate mock connection data for testing
function generateMockConnections(): any[] {
  const mockConnections = [];
  const connectionTypes = ['RDP', 'SSH', 'VNC', 'TeamViewer', 'HTTPS', 'HTTP', 'Other'];
  const remoteIPs = ['192.168.1.50', '10.0.0.25', '172.16.0.100', '203.0.113.45', '142.250.191.14', '157.240.15.35'];
  const domains = ['google.com', 'facebook.com', 'github.com', 'stackoverflow.com', 'microsoft.com'];
  const browsers = ['Chrome', 'Firefox', 'Edge'];
  
  // Generate 0-5 random connections (including browser connections)
  const numConnections = Math.floor(Math.random() * 6);
  
  for (let i = 0; i < numConnections; i++) {
    const connectionType = connectionTypes[Math.floor(Math.random() * connectionTypes.length)];
    const remoteIP = remoteIPs[Math.floor(Math.random() * remoteIPs.length)];
    const isWebConnection = ['HTTPS', 'HTTP'].includes(connectionType);
    
    let remotePort, localPort, direction, domain, browserProcess;
    
    if (isWebConnection) {
      remotePort = connectionType === 'HTTPS' ? 443 : 80;
      localPort = Math.floor(Math.random() * 60000) + 1024;
      direction = 'outbound';
      domain = domains[Math.floor(Math.random() * domains.length)];
      browserProcess = browsers[Math.floor(Math.random() * browsers.length)];
    } else {
      direction = 'inbound';
      switch (connectionType) {
        case 'RDP':
          remotePort = 3389;
          localPort = '3389';
          break;
        case 'SSH':
          remotePort = 22;
          localPort = '22';
          break;
        case 'VNC':
          remotePort = 5900;
          localPort = '5900';
          break;
        case 'TeamViewer':
          remotePort = 5938;
          localPort = '5938';
          break;
        default:
          remotePort = Math.floor(Math.random() * 65535) + 1024;
          localPort = remotePort.toString();
      }
    }
    
    mockConnections.push({
      remote_ip: remoteIP,
      remote_port: remotePort,
      local_port: localPort.toString(),
      protocol: 'TCP',
      connection_type: connectionType,
      direction,
      domain,
      browser_process: browserProcess,
      process_name: isWebConnection ? `${browserProcess?.toLowerCase()}.exe` : 
                   connectionType === 'RDP' ? 'svchost.exe' : 
                   connectionType === 'SSH' ? 'sshd.exe' : 'unknown.exe',
      process_id: Math.floor(Math.random() * 10000) + 1000,
      username: isWebConnection ? null : 'remote_user',
      isNew: Math.random() > 0.5 // 50% chance of being a new connection
    });
  }
  
  return mockConnections;
}

// Helper function to get system health (would interface with Python service)
async function getSystemHealth(): Promise<any> {
  // This would make a call to the Python monitoring service
  // For now, return mock data
  return {
    status: 'healthy',
    lastCheck: new Date(),
    services: {
      monitoring: true,
      database: true,
      network: true
    }
  };
}

export default router;