import mongoose, { Document, Schema } from 'mongoose';

export interface IAlertConfig extends Document {
  userId: mongoose.Types.ObjectId;
  alertType: string;
  emailEnabled: boolean;
  desktopEnabled: boolean;
  thresholds: Record<string, any>;
  createdAt: Date;
}

const alertConfigSchema = new Schema<IAlertConfig>({
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  alertType: {
    type: String,
    required: true,
    enum: [
      'SUSPICIOUS_CONNECTION',
      'MULTIPLE_ATTEMPTS',
      'UNAUTHORIZED_ACCESS',
      'HIGH_RISK_IP',
      'UNUSUAL_ACTIVITY',
      'BLOCKED_CONNECTION'
    ]
  },
  emailEnabled: {
    type: Boolean,
    default: false
  },
  desktopEnabled: {
    type: Boolean,
    default: true
  },
  thresholds: {
    type: Schema.Types.Mixed,
    default: {
      maxConnections: 5,
      timeWindow: 300, // 5 minutes in seconds
      riskLevel: 'MEDIUM'
    }
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Index for efficient querying
alertConfigSchema.index({ userId: 1, alertType: 1 }, { unique: true });
alertConfigSchema.index({ alertType: 1 });

export const AlertConfig = mongoose.model<IAlertConfig>('AlertConfig', alertConfigSchema);