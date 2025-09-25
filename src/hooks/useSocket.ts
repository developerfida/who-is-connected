import { useEffect, useRef, useState } from 'react';
import { io, Socket } from 'socket.io-client';
import { useAuthStore } from '@/stores/authStore';

interface SocketData {
  connections?: any[];
  alerts?: any[];
  monitoring?: any;
  scanCompleted?: any;
  count?: number;
  timestamp?: string;
}

interface UseSocketOptions {
  autoConnect?: boolean;
  subscriptions?: string[];
}

interface UseSocketReturn {
  socket: Socket | null;
  isConnected: boolean;
  data: SocketData;
  subscribe: (event: string) => void;
  unsubscribe: (event: string) => void;
  emit: (event: string, data?: any) => void;
}

const SOCKET_URL = 'http://localhost:3001';

export const useSocket = (options: UseSocketOptions = {}): UseSocketReturn => {
  const { autoConnect = true, subscriptions = [] } = options;
  const { token, isAuthenticated } = useAuthStore();
  const socketRef = useRef<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [data, setData] = useState<SocketData>({});

  useEffect(() => {
    if (!isAuthenticated || !token || !autoConnect) {
      return;
    }

    // Create socket connection
    const socket = io(SOCKET_URL, {
      auth: {
        token
      },
      transports: ['websocket', 'polling'],
      timeout: 10000,
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000
    });

    socketRef.current = socket;

    // Connection event handlers
    socket.on('connect', () => {
      console.log('🔌 Connected to WebSocket server');
      setIsConnected(true);
      
      // Auto-subscribe to specified events
      subscriptions.forEach(subscription => {
        socket.emit(`subscribe:${subscription}`);
      });
    });

    socket.on('disconnect', (reason) => {
      console.log('🔌 Disconnected from WebSocket server:', reason);
      setIsConnected(false);
    });

    socket.on('connect_error', (error) => {
      console.error('❌ WebSocket connection error:', error);
      setIsConnected(false);
    });

    // Data event handlers
    socket.on('connections:update', (updateData) => {
      console.log('📡 Received connections update:', updateData);
      setData(prev => ({
        ...prev,
        connections: updateData.connections,
        count: updateData.count,
        timestamp: updateData.timestamp
      }));
    });

    socket.on('connection:new', (newConnectionData) => {
      console.log('🆕 New connection detected:', newConnectionData);
      setData(prev => ({
        ...prev,
        connections: prev.connections ? [newConnectionData.connection, ...prev.connections] : [newConnectionData.connection]
      }));
    });

    socket.on('connection:terminated', (terminatedData) => {
      console.log('🔚 Connection terminated:', terminatedData);
      setData(prev => ({
        ...prev,
        connections: prev.connections?.filter(conn => conn._id !== terminatedData.connectionId) || []
      }));
    });

    socket.on('alerts:update', (alertsData) => {
      console.log('🚨 Received alerts update:', alertsData);
      setData(prev => ({
        ...prev,
        alerts: alertsData.alerts,
        timestamp: alertsData.timestamp
      }));
    });

    socket.on('alert:new', (newAlertData) => {
      console.log('🚨 New security alert:', newAlertData);
      setData(prev => ({
        ...prev,
        alerts: prev.alerts ? [newAlertData.alert, ...prev.alerts] : [newAlertData.alert]
      }));
    });

    socket.on('monitoring:update', (monitoringData) => {
      console.log('📊 Received monitoring update:', monitoringData);
      setData(prev => ({
        ...prev,
        monitoring: monitoringData,
        timestamp: monitoringData.timestamp
      }));
    });

    socket.on('scan:completed', (scanData) => {
      console.log('🔍 Scan completed:', scanData);
      setData(prev => ({
        ...prev,
        scanCompleted: scanData,
        timestamp: scanData.timestamp
      }));
    });

    // Ping/pong for connection health
    socket.on('pong', (pongData) => {
      console.log('🏓 Pong received:', pongData);
    });

    // Cleanup on unmount
    return () => {
      console.log('🔌 Cleaning up WebSocket connection');
      socket.disconnect();
      socketRef.current = null;
      setIsConnected(false);
    };
  }, [isAuthenticated, token, autoConnect]);

  const subscribe = (event: string) => {
    if (socketRef.current && isConnected) {
      console.log(`📡 Subscribing to ${event}`);
      socketRef.current.emit(`subscribe:${event}`);
    }
  };

  const unsubscribe = (event: string) => {
    if (socketRef.current && isConnected) {
      console.log(`📡 Unsubscribing from ${event}`);
      socketRef.current.emit(`unsubscribe:${event}`);
    }
  };

  const emit = (event: string, eventData?: any) => {
    if (socketRef.current && isConnected) {
      socketRef.current.emit(event, eventData);
    }
  };

  return {
    socket: socketRef.current,
    isConnected,
    data,
    subscribe,
    unsubscribe,
    emit
  };
};

// Specialized hooks for different data types
export const useConnectionsSocket = () => {
  return useSocket({
    subscriptions: ['connections']
  });
};

export const useAlertsSocket = () => {
  return useSocket({
    subscriptions: ['alerts']
  });
};

export const useMonitoringSocket = () => {
  return useSocket({
    subscriptions: ['monitoring']
  });
};

export const useAllSocket = () => {
  return useSocket({
    subscriptions: ['connections', 'alerts', 'monitoring']
  });
};