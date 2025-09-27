/**
 * Database Migration Script: Fix Connection Directions
 * Updates existing ConnectionLog records with direction='unknown' to proper values
 */

const mongoose = require('mongoose');
require('dotenv').config();

// Define the ConnectionLog schema directly
const connectionLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  remoteIP: { type: String, required: true },
  remotePort: { type: Number, required: true },
  localPort: { type: String, required: true },
  protocol: { type: String, enum: ['TCP', 'UDP'], required: true },
  connectionType: { type: String, enum: ['RDP', 'SSH', 'VNC', 'TeamViewer', 'HTTP', 'HTTPS', 'HTTP_ALT', 'WEB', 'WebSocket', 'Other'], default: 'Other' },
  direction: { type: String, enum: ['inbound', 'outbound', 'local', 'unknown'], required: true, default: 'unknown' },
  domain: { type: String },
  processName: { type: String },
  processId: { type: Number },
  username: { type: String },
  startTime: { type: Date, default: Date.now, required: true },
  endTime: { type: Date },
  status: { type: String, enum: ['active', 'closed', 'blocked'], default: 'active' },
  isBlocked: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const ConnectionLog = mongoose.model('ConnectionLog', connectionLogSchema);

// Connect to MongoDB
const connectDatabase = async () => {
  try {
    const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/remote-monitor';
    await mongoose.connect(mongoUri);
    console.log('✅ Connected to MongoDB');
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    process.exit(1);
  }
};

// Function to determine connection direction based on connection details
const determineDirection = (connection) => {
  const { localPort, remoteIP, processName, remotePort } = connection;
  
  // Check for localhost connections
  if (remoteIP === '127.0.0.1' || remoteIP === '::1') {
    return 'local';
  }
  
  // Check for common remote access ports (inbound)
  const remoteAccessPorts = [3389, 22, 5900, 5901, 5938, 5985, 5986];
  if (remoteAccessPorts.includes(parseInt(localPort))) {
    return 'inbound';
  }
  
  // Check if it's a browser process with web traffic (outbound)
  if (processName) {
    const processNameLower = processName.toLowerCase();
    const browserProcesses = [
      'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe',
      'opera.exe', 'brave.exe', 'vivaldi.exe', 'safari.exe'
    ];
    
    const isBrowser = browserProcesses.some(browser => processNameLower.includes(browser));
    const isWebTraffic = [80, 443, 8080, 8443].includes(remotePort);
    
    if (isBrowser && isWebTraffic) {
      return 'outbound';
    }
    
    // Additional check for browser processes - if it's a browser, it's likely outbound
    if (isBrowser) {
      return 'outbound';
    }
  }
  
  // Check if it's an inbound connection by examining the process
  if (processName) {
    const processNameLower = processName.toLowerCase();
    const remoteProcesses = ['svchost.exe', 'winlogon.exe', 'rdpclip.exe', 'dwm.exe'];
    
    if (remoteProcesses.some(proc => processNameLower.includes(proc))) {
      return 'inbound';
    }
  }
  
  // Check for HTTPS connections (almost always outbound)
  if (remotePort === 443 || remotePort === 80) {
    return 'outbound';
  }
  
  // Check for private IP ranges (likely local network)
  const isPrivateIP = (ip) => {
    const parts = ip.split('.').map(Number);
    return (
      (parts[0] === 10) ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168)
    );
  };
  
  if (isPrivateIP(remoteIP)) {
    // For private IPs, assume outbound unless it's a known inbound service
    return 'outbound';
  }
  
  // Most other connections are outbound
  return 'outbound';
};

// Main migration function
const fixConnectionDirections = async () => {
  try {
    console.log('🔍 Finding connections with unknown direction...');
    
    // Find all connections with direction='unknown'
    const unknownConnections = await ConnectionLog.find({ direction: 'unknown' });
    
    console.log(`📊 Found ${unknownConnections.length} connections with unknown direction`);
    
    if (unknownConnections.length === 0) {
      console.log('✅ No connections need updating');
      return;
    }
    
    let updatedCount = 0;
    const directionStats = {
      inbound: 0,
      outbound: 0,
      local: 0
    };
    
    // Process each connection
    for (const connection of unknownConnections) {
      const newDirection = determineDirection(connection);
      
      // Update the connection
      await ConnectionLog.updateOne(
        { _id: connection._id },
        { direction: newDirection }
      );
      
      updatedCount++;
      directionStats[newDirection]++;
      
      // Log progress every 100 updates
      if (updatedCount % 100 === 0) {
        console.log(`📝 Updated ${updatedCount}/${unknownConnections.length} connections...`);
      }
    }
    
    console.log('\n✅ Migration completed successfully!');
    console.log(`📊 Updated ${updatedCount} connections:`);
    console.log(`   - Inbound: ${directionStats.inbound}`);
    console.log(`   - Outbound: ${directionStats.outbound}`);
    console.log(`   - Local: ${directionStats.local}`);
    
  } catch (error) {
    console.error('❌ Error during migration:', error);
    throw error;
  }
};

// Run the migration
const runMigration = async () => {
  try {
    await connectDatabase();
    await fixConnectionDirections();
    console.log('\n🎉 Migration script completed successfully!');
  } catch (error) {
    console.error('❌ Migration failed:', error);
  } finally {
    await mongoose.connection.close();
    console.log('📝 Database connection closed');
    process.exit(0);
  }
};

// Execute if run directly
if (require.main === module) {
  runMigration();
}

module.exports = { fixConnectionDirections, determineDirection };