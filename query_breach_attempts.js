import mongoose from 'mongoose';

async function queryBreachAttempts() {
  try {
    // Connect to MongoDB
    await mongoose.connect('mongodb://localhost:27017/remote-connection-monitor');
    
    console.log('Connected to MongoDB');
    
    // List all collections in the database
    const collections = await mongoose.connection.db.listCollections().toArray();
    console.log('\n📋 Available collections in database:');
    collections.forEach(col => console.log(`   - ${col.name}`));
    
    // Define schemas directly
    const securityAlertSchema = new mongoose.Schema({}, { strict: false });
    const connectionLogSchema = new mongoose.Schema({}, { strict: false });
    
    const SecurityAlert = mongoose.model('SecurityAlert', securityAlertSchema, 'securityalerts');
    const ConnectionLog = mongoose.model('ConnectionLog', connectionLogSchema, 'connectionlogs');
    
    // Check total documents in each collection
    const alertCount = await SecurityAlert.countDocuments();
    const connectionCount = await ConnectionLog.countDocuments();
    
    console.log(`\n📊 Database Statistics:`);
    console.log(`   - Security Alerts: ${alertCount}`);
    console.log(`   - Connection Logs: ${connectionCount}`);
    
    if (alertCount > 0) {
      // Get all alert types
      const allAlertTypes = await SecurityAlert.distinct('alertType');
      console.log(`\n📋 Available alert types: ${allAlertTypes.join(', ')}`);
      
      // Get recent alerts of any type
       const recentAlerts = await SecurityAlert.find({})
         .sort({ createdAt: -1 })
         .limit(10);
      
      console.log(`\n🔍 Recent security alerts (last 10):`);
      recentAlerts.forEach((alert, index) => {
         // Extract IP from message if available
         const ipMatch = alert.message?.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
         const ip = ipMatch ? ipMatch[0] : 'Unknown';
         
         console.log(`${index + 1}. Type: ${alert.alertType}`);
         console.log(`   IP: ${ip}`);
         console.log(`   Message: ${alert.message}`);
         console.log(`   Severity: ${alert.severity}`);
         console.log(`   Time: ${alert.createdAt}`);
         console.log(`   Acknowledged: ${alert.acknowledged}`);
         console.log('   ---');
       });
      
      // Look specifically for SYSTEM_BREACH_ATTEMPT
       const breachAttempts = await SecurityAlert.find({
         alertType: 'SYSTEM_BREACH_ATTEMPT'
       });
      
      if (breachAttempts.length > 0) {
        console.log(`\n🚨 Found ${breachAttempts.length} SYSTEM_BREACH_ATTEMPT alerts:`);
         breachAttempts.forEach((alert, index) => {
           // Extract IP from message
           const ipMatch = alert.message?.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
           const ip = ipMatch ? ipMatch[0] : 'Unknown';
           console.log(`${index + 1}. IP: ${ip}`);
           console.log(`   Message: ${alert.message}`);
           console.log(`   Severity: ${alert.severity}`);
           console.log(`   Time: ${alert.createdAt}`);
           console.log(`   Acknowledged: ${alert.acknowledged}`);
           console.log('   ---');
         });
         
         // Extract unique IPs from breach attempts
         const uniqueIPs = [...new Set(breachAttempts
           .map(alert => {
             const ipMatch = alert.message?.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
             return ipMatch ? ipMatch[0] : null;
           })
           .filter(ip => ip)
         )];
         
         console.log(`\n📊 Summary: ${uniqueIPs.length} unique IP addresses involved in SYSTEM_BREACH_ATTEMPT alerts:`);
         uniqueIPs.forEach(ip => console.log(`   - ${ip}`));
      } else {
        console.log(`\n❌ No SYSTEM_BREACH_ATTEMPT alerts found.`);
      }
      
    } else {
      console.log('\n❌ No security alerts found in database.');
    }
    
    if (connectionCount > 0) {
      // Get recent connections
      const recentConnections = await ConnectionLog.find({})
        .sort({ createdAt: -1 })
        .limit(5);
      
      console.log(`\n🔗 Recent connections (last 5):`);
      recentConnections.forEach((conn, index) => {
        console.log(`${index + 1}. ${conn.remoteIP}:${conn.remotePort} (${conn.connectionType})`);
        if (conn.geoLocation) {
          console.log(`   Location: ${conn.geoLocation.city}, ${conn.geoLocation.country}`);
        }
        console.log(`   Status: ${conn.status}`);
        console.log('   ---');
      });
    }
    
  } catch (error) {
    console.error('❌ Error querying database:', error);
  } finally {
    await mongoose.disconnect();
    console.log('\n✅ Disconnected from MongoDB');
  }
}

// Run the query
queryBreachAttempts();