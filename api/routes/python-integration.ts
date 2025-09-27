/**
 * Python Integration API routes
 * Handle data from Python monitoring service
 */
import { Router, type Response, type Request } from 'express';
import Joi from 'joi';
import { ConnectionLog, SecurityAlert, User } from '../models';
import { broadcastNewConnection, broadcastSecurityAlert, broadcastConnectionTerminated } from '../websocket/handlers.js';

const router = Router();

// Validation schemas
const geoLocationSchema = Joi.object({
  country: Joi.string().allow(''),
  countryCode: Joi.string().allow(''),
  city: Joi.string().allow(''),
  region: Joi.string().allow(''),
  regionName: Joi.string().allow(''),
  isp: Joi.string().allow(''),
  org: Joi.string().allow(''),
  asn: Joi.string().allow(''),
  timezone: Joi.string().allow(''),
  lat: Joi.number(),
  lon: Joi.number(),
  query: Joi.string().allow(''),
  status: Joi.string().allow('')
});

const newConnectionSchema = Joi.object({
  local_ip: Joi.string().ip(),
  local_port: Joi.alternatives().try(Joi.string(), Joi.number()).required(),
  remote_ip: Joi.string().ip().required(),
  remote_port: Joi.number().integer().min(1).max(65535).required(),
  protocol: Joi.string().valid('TCP', 'UDP').required(),
  connection_type: Joi.string().valid('RDP', 'SSH', 'VNC', 'TeamViewer', 'HTTP', 'HTTPS', 'WebSocket', 'Other').default('Other'),
  direction: Joi.string().valid('inbound', 'outbound', 'local', 'unknown').default('unknown'),
  process_name: Joi.string().allow(''),
  pid: Joi.number().integer().min(0),
  username: Joi.string().allow(''),
  timestamp: Joi.string().isoDate().required(),
  geoLocation: geoLocationSchema.optional()
});

const systemInfoSchema = Joi.object({
  timestamp: Joi.string().isoDate().required(),
  cpu: Joi.object({
    usage_percent: Joi.number().min(0).max(100),
    count: Joi.number().integer().min(1),
    count_logical: Joi.number().integer().min(1),
    freq: Joi.object().allow(null)
  }),
  memory: Joi.object({
    total: Joi.number().min(0),
    available: Joi.number().min(0),
    used: Joi.number().min(0),
    percent: Joi.number().min(0).max(100)
  }),
  disk: Joi.object({
    total: Joi.number().min(0),
    used: Joi.number().min(0),
    free: Joi.number().min(0),
    percent: Joi.number().min(0).max(100)
  }),
  network: Joi.object({
    bytes_sent: Joi.number().min(0),
    bytes_recv: Joi.number().min(0),
    packets_sent: Joi.number().min(0),
    packets_recv: Joi.number().min(0)
  }),
  boot_time: Joi.string().isoDate()
});

// Simple API key authentication for Python service
const PYTHON_API_KEY = process.env.PYTHON_API_KEY || 'python-monitor-key-change-in-production';

const authenticatePythonService = (req: Request, res: Response, next: Function) => {
  const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
  
  if (!apiKey || apiKey !== PYTHON_API_KEY) {
    return res.status(401).json({
      success: false,
      message: 'Invalid API key for Python service'
    });
  }
  
  next();
};

/**
 * Receive New Connection from Python Service
 * POST /api/python/connections/new
 */
router.post('/connections/new', authenticatePythonService, async (req: Request, res: Response): Promise<void> => {
  try {
    const { error, value } = newConnectionSchema.validate(req.body);
    if (error) {
      console.error('🚨 Validation error for new connection:', {
        error: error.details[0].message,
        receivedData: req.body
      });
      res.status(400).json({
        success: false,
        message: 'Validation error',
        details: error.details[0].message
      });
      return;
    }

    // Get default admin user (or create a system user)
    let systemUser = await User.findOne({ username: 'system' });
    if (!systemUser) {
      // Use admin user as fallback
      systemUser = await User.findOne({ role: 'admin' });
      if (!systemUser) {
        res.status(500).json({
          success: false,
          message: 'No system user found to associate connection'
        });
        return;
      }
    }

    // Create connection log entry
    const connectionLog = new ConnectionLog({
      userId: systemUser._id,
      remoteIP: value.remote_ip,
      remotePort: value.remote_port,
      localPort: value.local_port.toString(),
      protocol: value.protocol,
      connectionType: value.connection_type,
      direction: value.direction || 'unknown',
      processName: value.process_name || undefined,
      processId: value.pid || undefined,
      username: value.username || undefined,
      startTime: new Date(value.timestamp),
      status: 'active',
      isBlocked: false,
      geoLocation: value.geoLocation || undefined
    });

    await connectionLog.save();

    // Check for suspicious activity and create alerts
    await checkForSuspiciousActivity(connectionLog);

    // Broadcast to WebSocket clients
    broadcastNewConnection(connectionLog);

    res.json({
      success: true,
      message: 'Connection logged successfully',
      connectionId: connectionLog._id
    });
  } catch (error) {
    console.error('Error processing new connection:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while processing connection'
    });
  }
});

/**
 * Receive Connection Closed from Python Service
 * POST /api/python/connections/closed
 */
router.post('/connections/closed', authenticatePythonService, async (req: Request, res: Response): Promise<void> => {
  try {
    const { remote_ip, remote_port, local_port, timestamp } = req.body;

    if (!remote_ip || !remote_port || !local_port || !timestamp) {
      res.status(400).json({
        success: false,
        message: 'Missing required fields: remote_ip, remote_port, local_port, timestamp'
      });
      return;
    }

    // Find and update the connection
    const connection = await ConnectionLog.findOne({
      remoteIP: remote_ip,
      remotePort: remote_port,
      localPort: local_port.toString(),
      status: 'active'
    }).sort({ startTime: -1 }); // Get the most recent active connection

    if (connection) {
      connection.status = 'closed';
      connection.endTime = new Date(timestamp);
      await connection.save();

      // Broadcast connection termination
      broadcastConnectionTerminated(connection._id.toString());

      res.json({
        success: true,
        message: 'Connection closed successfully',
        connectionId: connection._id
      });
    } else {
      res.status(404).json({
        success: false,
        message: 'Active connection not found'
      });
    }
  } catch (error) {
    console.error('Error processing connection closure:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while processing connection closure'
    });
  }
});

/**
 * Receive System Information from Python Service
 * POST /api/python/monitoring/system-info
 */
router.post('/monitoring/system-info', authenticatePythonService, async (req: Request, res: Response): Promise<void> => {
  try {
    const { error, value } = systemInfoSchema.validate(req.body);
    if (error) {
      res.status(400).json({
        success: false,
        message: 'Validation error',
        details: error.details[0].message
      });
      return;
    }

    // Store system info (you might want to create a SystemInfo model)
    // For now, we'll just acknowledge receipt and could broadcast to monitoring clients
    
    console.log('📊 Received system info from Python service:', {
      timestamp: value.timestamp,
      cpu: value.cpu?.usage_percent,
      memory: value.memory?.percent,
      disk: value.disk?.percent
    });

    // TODO: Broadcast to monitoring WebSocket clients
    // broadcastSystemInfo(value);

    res.json({
      success: true,
      message: 'System information received successfully'
    });
  } catch (error) {
    console.error('Error processing system info:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while processing system info'
    });
  }
});

/**
 * Receive Security Alert from Python Service
 * POST /api/python/security/alert
 */
router.post('/security/alert', authenticatePythonService, async (req: Request, res: Response): Promise<void> => {
  try {
    const { alert_type, severity, message, connection_id } = req.body;

    // Enhanced logging for debugging
    console.log('🚨 Received security alert from Python service:', {
      alert_type,
      severity,
      message: message?.substring(0, 100) + (message?.length > 100 ? '...' : ''),
      connection_id,
      timestamp: new Date().toISOString()
    });

    if (!alert_type || !severity || !message) {
      console.error('❌ Security alert validation failed:', {
        alert_type: !!alert_type,
        severity: !!severity,
        message: !!message,
        receivedBody: req.body
      });
      res.status(400).json({
        success: false,
        message: 'Missing required fields: alert_type, severity, message'
      });
      return;
    }

    // Validate severity level
    const validSeverities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    if (!validSeverities.includes(severity.toUpperCase())) {
      console.error('❌ Invalid severity level:', { severity, validSeverities });
      res.status(400).json({
        success: false,
        message: `Invalid severity level. Must be one of: ${validSeverities.join(', ')}`
      });
      return;
    }

    // Create security alert
    const alert = new SecurityAlert({
      connectionId: connection_id || undefined,
      alertType: alert_type,
      severity: severity.toUpperCase(),
      message: message,
      acknowledged: false
    });

    await alert.save();
    console.log('✅ Security alert saved to database:', {
      alertId: alert._id,
      alertType: alert.alertType,
      severity: alert.severity,
      timestamp: alert.createdAt
    });

    // Broadcast to WebSocket clients
    try {
      broadcastSecurityAlert(alert);
      console.log('📡 Security alert broadcasted via WebSocket:', {
        alertId: alert._id,
        severity: alert.severity
      });
    } catch (broadcastError) {
      console.error('❌ Failed to broadcast security alert:', broadcastError);
      // Don't fail the request if broadcast fails
    }

    res.json({
      success: true,
      message: 'Security alert created successfully',
      alertId: alert._id
    });
  } catch (error) {
    console.error('❌ Error processing security alert:', {
      error: error instanceof Error ? error.message : error,
      stack: error instanceof Error ? error.stack : undefined,
      requestBody: req.body
    });
    res.status(500).json({
      success: false,
      message: 'Internal server error while processing security alert'
    });
  }
});

/**
 * Health Check for Python Service
 * GET /api/python/health
 */
router.get('/health', authenticatePythonService, async (req: Request, res: Response): Promise<void> => {
  res.json({
    success: true,
    message: 'Python integration API is healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

/**
 * Helper function to check for suspicious activity
 */
async function checkForSuspiciousActivity(connection: any): Promise<void> {
  try {
    const now = new Date();
    const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000);

    // Check for multiple connections from same IP in short time
    const recentConnections = await ConnectionLog.countDocuments({
      remoteIP: connection.remoteIP,
      startTime: { $gte: fiveMinutesAgo }
    });

    if (recentConnections > 3) {
      const alert = new SecurityAlert({
        connectionId: connection._id,
        alertType: 'MULTIPLE_ATTEMPTS',
        severity: 'HIGH',
        message: `Multiple connection attempts (${recentConnections}) from ${connection.remoteIP} in the last 5 minutes`,
        acknowledged: false
      });
      await alert.save();
      broadcastSecurityAlert(alert);
    }

    // Check for connections from unusual ports
    const unusualPorts = [1234, 4444, 5555, 6666, 7777, 8888, 9999];
    if (unusualPorts.includes(connection.remotePort)) {
      const alert = new SecurityAlert({
        connectionId: connection._id,
        alertType: 'SUSPICIOUS_IP',
        severity: 'MEDIUM',
        message: `Connection from unusual port ${connection.remotePort} detected from ${connection.remoteIP}`,
        acknowledged: false
      });
      await alert.save();
      broadcastSecurityAlert(alert);
    }

    // Check for non-standard connection types on standard ports
    if (connection.localPort === '3389' && connection.connectionType !== 'RDP') {
      const alert = new SecurityAlert({
        connectionId: connection._id,
        alertType: 'UNUSUAL_ACTIVITY',
        severity: 'MEDIUM',
        message: `Non-RDP connection detected on RDP port 3389 from ${connection.remoteIP}`,
        acknowledged: false
      });
      await alert.save();
      broadcastSecurityAlert(alert);
    }
  } catch (error) {
    console.error('Error checking for suspicious activity:', error);
  }
}

export default router;