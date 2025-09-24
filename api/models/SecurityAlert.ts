import mongoose, { Document, Schema } from 'mongoose';

export interface ISecurityAlert extends Document {
  connectionId?: mongoose.Types.ObjectId;
  alertType: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  message: string;
  acknowledged: boolean;
  createdAt: Date;
}

const securityAlertSchema = new Schema<ISecurityAlert>({
  connectionId: {
    type: Schema.Types.ObjectId,
    ref: 'ConnectionLog'
  },
  alertType: {
    type: String,
    required: true,
    enum: [
      'SUSPICIOUS_IP',
      'SUSPICIOUS_CONNECTION',
      'MULTIPLE_ATTEMPTS',
      'UNAUTHORIZED_ACCESS',
      'HIGH_RISK_CONNECTION',
      'BLOCKED_CONNECTION',
      'UNUSUAL_ACTIVITY',
      'SYSTEM_BREACH_ATTEMPT'
    ]
  },
  severity: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    required: true
  },
  message: {
    type: String,
    required: true,
    trim: true,
    maxlength: 500
  },
  acknowledged: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Indexes for efficient querying
securityAlertSchema.index({ createdAt: -1 });
securityAlertSchema.index({ severity: 1, acknowledged: 1 });
securityAlertSchema.index({ alertType: 1 });
securityAlertSchema.index({ connectionId: 1 });

export const SecurityAlert = mongoose.model<ISecurityAlert>('SecurityAlert', securityAlertSchema);