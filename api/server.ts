/**
 * Remote Connection Monitor Server with WebSocket support
 */
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import app from './app.js';
import { setupWebSocketHandlers, setIOInstance } from './websocket/handlers.js';

/**
 * start server with port
 */
const PORT = process.env.PORT || 3004;

// Create HTTP server
const server = createServer(app);

// Setup Socket.IO
const io = new SocketIOServer(server, {
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    methods: ['GET', 'POST'],
    credentials: true
  },
  transports: ['websocket', 'polling']
});

// Setup WebSocket event handlers
setupWebSocketHandlers(io);

// Set IO instance for broadcasting
setIOInstance(io);

// Start server
server.listen(PORT, () => {
  console.log(`🚀 Server ready on port ${PORT}`);
  console.log(`📡 WebSocket server ready for real-time connections`);
});

// Export io instance for use in other modules
export { io };

/**
 * close server
 */
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT signal received');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

export default app;

