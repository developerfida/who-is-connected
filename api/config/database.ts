import mongoose from 'mongoose';
import { User } from '../models/User';
import { AlertConfig } from '../models/AlertConfig';

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/remote-connection-monitor';

export const connectDatabase = async (): Promise<void> => {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB successfully');
    
    // Initialize default data
    await initializeDefaultData();
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    process.exit(1);
  }
};

export const disconnectDatabase = async (): Promise<void> => {
  try {
    await mongoose.disconnect();
    console.log('✅ Disconnected from MongoDB');
  } catch (error) {
    console.error('❌ Error disconnecting from MongoDB:', error);
  }
};

// Initialize default admin user and configurations
const initializeDefaultData = async (): Promise<void> => {
  try {
    // Check if admin user exists
    const adminExists = await User.findOne({ username: 'admin' });
    
    if (!adminExists) {
      // Create default admin user
      const adminUser = new User({
        username: 'admin',
        passwordHash: 'admin123', // Will be hashed by pre-save hook
        role: 'admin'
      });
      
      await adminUser.save();
      console.log('✅ Default admin user created (username: admin, password: admin123)');
      
      // Create default alert configurations for admin
      const defaultAlertConfigs = [
        {
          userId: adminUser._id,
          alertType: 'SUSPICIOUS_CONNECTION',
          emailEnabled: false,
          desktopEnabled: true,
          thresholds: { maxConnections: 5, timeWindow: 300, riskLevel: 'MEDIUM' }
        },
        {
          userId: adminUser._id,
          alertType: 'MULTIPLE_ATTEMPTS',
          emailEnabled: false,
          desktopEnabled: true,
          thresholds: { maxAttempts: 3, timeWindow: 180 }
        },
        {
          userId: adminUser._id,
          alertType: 'UNAUTHORIZED_ACCESS',
          emailEnabled: true,
          desktopEnabled: true,
          thresholds: { riskLevel: 'HIGH' }
        }
      ];
      
      await AlertConfig.insertMany(defaultAlertConfigs);
      console.log('✅ Default alert configurations created');
    }
  } catch (error) {
    console.error('❌ Error initializing default data:', error);
  }
};

// Handle graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🔄 Gracefully shutting down...');
  await disconnectDatabase();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n🔄 Gracefully shutting down...');
  await disconnectDatabase();
  process.exit(0);
});