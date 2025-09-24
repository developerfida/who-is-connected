/**
 * WebSocket handlers for real-time communication
 */
import { Server as SocketIOServer, Socket } from 'socket.io';
import jwt from 'jsonwebtoken';
import { User } from '../models/User.js';
import { ConnectionLog, SecurityAlert } from '../models/index.js';

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

interface AuthenticatedSocket extends Socket {
  userId?: string;
  userRole?: string;
}

// Store connected clients
const connectedClients = new Map<string, AuthenticatedSocket>();

/**
 * Setup WebSocket event handlers
 */
export function setupWebSocketHandlers(io: SocketIOServer): void {
  // Authentication middleware for Socket.IO
  io.use(async (socket: AuthenticatedSocket, next) => {
    try {
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
      
      if (!token) {
        return next(new Error('Authentication token required'));
      }

      const decoded = jwt.verify(token, JWT_SECRET) as any;
      const user = await User.findById(decoded.userId).select('-passwordHash');
      
      if (!user) {
        return next(new Error('User not found'));
      }

      socket.userId = user._id.toString();
      socket.userRole = user.role;
      next();
    } catch (error) {
      next(new Error('Invalid authentication token'));
    }
  });

  // Handle client connections
  io.on('connection', (socket: AuthenticatedSocket) => {
    console.log(`🔌 Client connected: ${socket.id} (User: ${socket.userId})`);
    
    // Store the connected client
    if (socket.userId) {
      connectedClients.set(socket.userId, socket);
    }

    // Join user-specific room
    if (socket.userId) {
      socket.join(`user:${socket.userId}`);
      
      // Join admin room if user is admin
      if (socket.userRole === 'admin') {
        socket.join('admin');
      }
    }

    // Handle subscription to real-time connection updates
    socket.on('subscribe:connections', () => {
      console.log(`📡 Client ${socket.id} subscribed to connection updates`);
      socket.join('connections');
      
      // Send initial connection data
      sendActiveConnections(socket);
    });

    // Handle subscription to security alerts
    socket.on('subscribe:alerts', () => {
      console.log(`🚨 Client ${socket.id} subscribed to security alerts`);
      socket.join('alerts');
      
      // Send initial alerts data
      sendSecurityAlerts(socket);
    });

    // Handle subscription to system monitoring
    socket.on('subscribe:monitoring', () => {
      console.log(`📊 Client ${socket.id} subscribed to system monitoring`);
      socket.join('monitoring');
      
      // Send initial monitoring data
      sendSystemStatus(socket);
    });

    // Handle unsubscription
    socket.on('unsubscribe:connections', () => {
      socket.leave('connections');
    });

    socket.on('unsubscribe:alerts', () => {
      socket.leave('alerts');
    });

    socket.on('unsubscribe:monitoring', () => {
      socket.leave('monitoring');
    });

    // Handle client disconnection
    socket.on('disconnect', (reason) => {
      console.log(`🔌 Client disconnected: ${socket.id} (Reason: ${reason})`);
      
      if (socket.userId) {
        connectedClients.delete(socket.userId);
      }
    });

    // Handle ping/pong for connection health
    socket.on('ping', () => {
      socket.emit('pong', { timestamp: Date.now() });
    });
  });

  // Start periodic updates
  startPeriodicUpdates(io);
}

/**
 * Send active connections to a specific socket
 */
async function sendActiveConnections(socket: AuthenticatedSocket): Promise<void> {
  try {
    if (!socket.userId) return;

    const connections = await ConnectionLog.find({
      userId: socket.userId,
      status: 'active'
    }).sort({ startTime: -1 });

    socket.emit('connections:update', {
      connections,
      count: connections.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error sending active connections:', error);
  }
}

/**
 * Send security alerts to a specific socket
 */
async function sendSecurityAlerts(socket: AuthenticatedSocket): Promise<void> {
  try {
    const alerts = await SecurityAlert.find({
      acknowledged: false
    })
    .sort({ createdAt: -1 })
    .limit(10)
    .populate('connectionId', 'remoteIP remotePort connectionType');

    socket.emit('alerts:update', {
      alerts,
      count: alerts.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error sending security alerts:', error);
  }
}

/**
 * Send system status to a specific socket
 */
async function sendSystemStatus(socket: AuthenticatedSocket): Promise<void> {
  try {
    // Mock system status (would be replaced with actual system monitoring)
    const systemStatus = {
      cpu: Math.floor(Math.random() * 30) + 10,
      memory: Math.floor(Math.random() * 30) + 20,
      network: {
        bytesIn: Math.floor(Math.random() * 1000000),
        bytesOut: Math.floor(Math.random() * 500000)
      },
      activeConnections: await ConnectionLog.countDocuments({
        userId: socket.userId,
        status: 'active'
      }),
      timestamp: new Date().toISOString()
    };

    socket.emit('monitoring:update', systemStatus);
  } catch (error) {
    console.error('Error sending system status:', error);
  }
}

/**
 * Start periodic updates for real-time data
 */
function startPeriodicUpdates(io: SocketIOServer): void {
  // Update connections every 5 seconds
  setInterval(async () => {
    try {
      const connectionsRoom = io.sockets.adapter.rooms.get('connections');
      if (connectionsRoom && connectionsRoom.size > 0) {
        // Broadcast to all clients subscribed to connections
        for (const socketId of connectionsRoom) {
          const socket = io.sockets.sockets.get(socketId) as AuthenticatedSocket;
          if (socket && socket.userId) {
            await sendActiveConnections(socket);
          }
        }
      }
    } catch (error) {
      console.error('Error in periodic connections update:', error);
    }
  }, 5000);

  // Update system monitoring every 10 seconds
  setInterval(async () => {
    try {
      const monitoringRoom = io.sockets.adapter.rooms.get('monitoring');
      if (monitoringRoom && monitoringRoom.size > 0) {
        for (const socketId of monitoringRoom) {
          const socket = io.sockets.sockets.get(socketId) as AuthenticatedSocket;
          if (socket && socket.userId) {
            await sendSystemStatus(socket);
          }
        }
      }
    } catch (error) {
      console.error('Error in periodic monitoring update:', error);
    }
  }, 10000);

  // Check for new alerts every 30 seconds
  setInterval(async () => {
    try {
      const alertsRoom = io.sockets.adapter.rooms.get('alerts');
      if (alertsRoom && alertsRoom.size > 0) {
        for (const socketId of alertsRoom) {
          const socket = io.sockets.sockets.get(socketId) as AuthenticatedSocket;
          if (socket) {
            await sendSecurityAlerts(socket);
          }
        }
      }
    } catch (error) {
      console.error('Error in periodic alerts update:', error);
    }
  }, 30000);
}

/**
 * Broadcast new connection to all subscribed clients
 */
export function broadcastNewConnection(connection: any): void {
  const io = getIOInstance();
  if (io) {
    io.to('connections').emit('connection:new', {
      connection,
      timestamp: new Date().toISOString()
    });
  }
}

/**
 * Broadcast new security alert to all subscribed clients
 */
export function broadcastSecurityAlert(alert: any): void {
  const io = getIOInstance();
  if (io) {
    io.to('alerts').emit('alert:new', {
      alert,
      timestamp: new Date().toISOString()
    });
  }
}

/**
 * Broadcast connection termination to all subscribed clients
 */
export function broadcastConnectionTerminated(connectionId: string): void {
  const io = getIOInstance();
  if (io) {
    io.to('connections').emit('connection:terminated', {
      connectionId,
      timestamp: new Date().toISOString()
    });
  }
}

/**
 * Broadcast scan completion to all subscribed clients
 */
export function broadcastScanCompleted(scanData: any): void {
  const io = getIOInstance();
  if (io) {
    // Broadcast to both connections and monitoring rooms
    io.to('connections').emit('scan:completed', {
      ...scanData,
      timestamp: new Date().toISOString()
    });
    io.to('monitoring').emit('scan:completed', {
      ...scanData,
      timestamp: new Date().toISOString()
    });
  }
}

// Store IO instance reference
let ioInstance: SocketIOServer | null = null;

/**
 * Set the IO instance (called from server.ts)
 */
export function setIOInstance(io: SocketIOServer): void {
  ioInstance = io;
}

// Helper to get IO instance
function getIOInstance(): SocketIOServer | null {
  return ioInstance;
}

/**
 * Get connected clients count
 */
export function getConnectedClientsCount(): number {
  return connectedClients.size;
}

/**
 * Send message to specific user
 */
export function sendToUser(userId: string, event: string, data: any): void {
  const socket = connectedClients.get(userId);
  if (socket) {
    socket.emit(event, data);
  }
}

/**
 * Send message to all admin users
 */
export function sendToAdmins(event: string, data: any): void {
  const io = getIOInstance();
  if (io) {
    io.to('admin').emit(event, data);
  }
}