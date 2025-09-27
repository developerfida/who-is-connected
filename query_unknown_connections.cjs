/**
 * Query Script: Find Connections with Unknown Direction
 * Analyzes connections that still have direction='unknown' to identify patterns
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

// Main query function
const queryUnknownConnections = async () => {
  try {
    console.log('🔍 Querying connections with unknown direction...');
    
    // Find all connections with direction='unknown'
    const unknownConnections = await ConnectionLog.find({ direction: 'unknown' })
      .select('remoteIP remotePort localPort processName connectionType protocol status createdAt')
      .sort({ createdAt: -1 })
      .limit(50); // Limit to 50 most recent for analysis
    
    console.log(`\n📊 Found ${unknownConnections.length} connections with unknown direction`);
    
    if (unknownConnections.length === 0) {
      console.log('✅ No connections with unknown direction found!');
      return;
    }
    
    // Get total count
    const totalUnknown = await ConnectionLog.countDocuments({ direction: 'unknown' });
    console.log(`📈 Total unknown connections in database: ${totalUnknown}`);
    
    // Analyze patterns
    const patterns = {
      byConnectionType: {},
      byProcessName: {},
      byLocalPort: {},
      byRemotePort: {},
      byProtocol: {}
    };
    
    console.log('\n🔍 Analyzing patterns in unknown connections:');
    console.log('=' .repeat(80));
    
    unknownConnections.forEach((conn, index) => {
      // Count patterns
      patterns.byConnectionType[conn.connectionType] = (patterns.byConnectionType[conn.connectionType] || 0) + 1;
      patterns.byProcessName[conn.processName || 'null'] = (patterns.byProcessName[conn.processName || 'null'] || 0) + 1;
      patterns.byLocalPort[conn.localPort] = (patterns.byLocalPort[conn.localPort] || 0) + 1;
      patterns.byRemotePort[conn.remotePort] = (patterns.byRemotePort[conn.remotePort] || 0) + 1;
      patterns.byProtocol[conn.protocol] = (patterns.byProtocol[conn.protocol] || 0) + 1;
      
      // Display first 10 connections in detail
      if (index < 10) {
        console.log(`\n${index + 1}. Connection Details:`);
        console.log(`   Remote IP: ${conn.remoteIP}:${conn.remotePort}`);
        console.log(`   Local Port: ${conn.localPort}`);
        console.log(`   Process: ${conn.processName || 'Unknown'}`);
        console.log(`   Type: ${conn.connectionType}`);
        console.log(`   Protocol: ${conn.protocol}`);
        console.log(`   Status: ${conn.status}`);
        console.log(`   Created: ${conn.createdAt.toISOString()}`);
      }
    });
    
    // Display pattern analysis
    console.log('\n\n📊 Pattern Analysis:');
    console.log('=' .repeat(50));
    
    console.log('\n🔗 By Connection Type:');
    Object.entries(patterns.byConnectionType)
      .sort(([,a], [,b]) => b - a)
      .forEach(([type, count]) => {
        console.log(`   ${type}: ${count}`);
      });
    
    console.log('\n⚙️  By Process Name:');
    Object.entries(patterns.byProcessName)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10) // Top 10
      .forEach(([process, count]) => {
        console.log(`   ${process}: ${count}`);
      });
    
    console.log('\n🔌 By Local Port:');
    Object.entries(patterns.byLocalPort)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10) // Top 10
      .forEach(([port, count]) => {
        console.log(`   ${port}: ${count}`);
      });
    
    console.log('\n🌐 By Remote Port:');
    Object.entries(patterns.byRemotePort)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10) // Top 10
      .forEach(([port, count]) => {
        console.log(`   ${port}: ${count}`);
      });
    
    console.log('\n📡 By Protocol:');
    Object.entries(patterns.byProtocol)
      .sort(([,a], [,b]) => b - a)
      .forEach(([protocol, count]) => {
        console.log(`   ${protocol}: ${count}`);
      });
    
    // Identify potential issues
    console.log('\n\n🚨 Potential Issues Identified:');
    console.log('=' .repeat(50));
    
    // Check for HTTPS connections that should be outbound
    const httpsUnknown = unknownConnections.filter(conn => 
      conn.connectionType === 'HTTPS' && 
      conn.processName && 
      conn.processName.toLowerCase().includes('chrome')
    );
    
    if (httpsUnknown.length > 0) {
      console.log(`⚠️  Found ${httpsUnknown.length} HTTPS Chrome connections that should be outbound`);
    }
    
    // Check for connections with missing process names
    const missingProcess = unknownConnections.filter(conn => !conn.processName);
    if (missingProcess.length > 0) {
      console.log(`⚠️  Found ${missingProcess.length} connections with missing process names`);
    }
    
    // Check for unusual port combinations
    const webPorts = [80, 443, 8080, 8443];
    const webTrafficUnknown = unknownConnections.filter(conn => 
      webPorts.includes(conn.remotePort) && 
      conn.processName && 
      conn.processName.toLowerCase().includes('chrome')
    );
    
    if (webTrafficUnknown.length > 0) {
      console.log(`⚠️  Found ${webTrafficUnknown.length} web traffic connections that should be outbound`);
    }
    
  } catch (error) {
    console.error('❌ Error during query:', error);
    throw error;
  }
};

// Run the query
const runQuery = async () => {
  try {
    await connectDatabase();
    await queryUnknownConnections();
    console.log('\n🎉 Query completed successfully!');
  } catch (error) {
    console.error('❌ Query failed:', error);
  } finally {
    await mongoose.connection.close();
    console.log('📝 Database connection closed');
    process.exit(0);
  }
};

// Execute if run directly
if (require.main === module) {
  runQuery();
}

module.exports = { queryUnknownConnections };