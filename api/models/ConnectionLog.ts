import mongoose, { Document, Schema } from 'mongoose';

export interface IConnectionLog extends Document {
  userId: mongoose.Types.ObjectId;
  remoteIP: string;
  remotePort: number;
  localPort: string;
  protocol: 'TCP' | 'UDP';
  connectionType: 'RDP' | 'SSH' | 'VNC' | 'TeamViewer' | 'HTTP' | 'HTTPS' | 'HTTP_ALT' | 'WEB' | 'WebSocket' | 'Other';
  direction: 'inbound' | 'outbound' | 'local' | 'unknown';
  domain?: string; // for outbound web connections
  browserProcess?: 'Chrome' | 'Firefox' | 'Edge' | 'Internet Explorer' | 'Opera' | 'Brave' | 'Vivaldi' | 'Safari';
  processName?: string;
  processId?: number;
  username?: string; // remote user
  isSuspicious?: boolean;
  securityRisk?: 'LOW' | 'MEDIUM' | 'HIGH';
  startTime: Date;
  endTime?: Date;
  status: 'active' | 'closed' | 'blocked';
  isBlocked: boolean;
  createdAt: Date;
}

const connectionLogSchema = new Schema<IConnectionLog>({
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  remoteIP: {
    type: String,
    required: true,
    validate: {
      validator: function(v: string) {
        // Basic IP validation
        return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(v);
      },
      message: 'Invalid IP address format'
    }
  },
  remotePort: {
    type: Number,
    required: true,
    min: 1,
    max: 65535
  },
  localPort: {
    type: String,
    required: true
  },
  protocol: {
    type: String,
    enum: ['TCP', 'UDP'],
    required: true
  },
  connectionType: {
    type: String,
    enum: ['RDP', 'SSH', 'VNC', 'TeamViewer', 'HTTP', 'HTTPS', 'HTTP_ALT', 'WEB', 'WebSocket', 'Other'],
    default: 'Other'
  },
  direction: {
    type: String,
    enum: ['inbound', 'outbound', 'local', 'unknown'],
    required: true,
    default: 'unknown'
  },
  domain: {
    type: String,
    trim: true
  },
  browserProcess: {
    type: String,
    enum: ['Chrome', 'Firefox', 'Edge', 'Internet Explorer', 'Opera', 'Brave', 'Vivaldi', 'Safari']
  },
  isSuspicious: {
    type: Boolean,
    default: false
  },
  securityRisk: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH'],
    default: 'LOW'
  },
  processName: {
    type: String,
    trim: true
  },
  processId: {
    type: Number,
    min: 0
  },
  username: {
    type: String,
    trim: true
  },
  startTime: {
    type: Date,
    default: Date.now,
    required: true
  },
  endTime: {
    type: Date
  },
  status: {
    type: String,
    enum: ['active', 'closed', 'blocked'],
    default: 'active'
  },
  isBlocked: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Indexes for efficient querying
connectionLogSchema.index({ userId: 1, startTime: -1 });
connectionLogSchema.index({ remoteIP: 1 });
connectionLogSchema.index({ status: 1 });
connectionLogSchema.index({ createdAt: -1 });
connectionLogSchema.index({ processId: 1 });
connectionLogSchema.index({ direction: 1 });
connectionLogSchema.index({ connectionType: 1 });
connectionLogSchema.index({ domain: 1 });
connectionLogSchema.index({ browserProcess: 1 });
connectionLogSchema.index({ isSuspicious: 1 });
connectionLogSchema.index({ securityRisk: 1 });
connectionLogSchema.index({ isSuspicious: 1, securityRisk: 1 });

export const ConnectionLog = mongoose.model<IConnectionLog>('ConnectionLog', connectionLogSchema);