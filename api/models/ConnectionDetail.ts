import mongoose, { Document, Schema } from 'mongoose';

export interface IConnectionDetail extends Document {
  connectionId: mongoose.Types.ObjectId;
  authMethod?: string;
  userAgent?: string;
  geoLocation?: string;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  metadata: Record<string, any>;
  createdAt: Date;
}

const connectionDetailSchema = new Schema<IConnectionDetail>({
  connectionId: {
    type: Schema.Types.ObjectId,
    ref: 'ConnectionLog',
    required: true,
    unique: true
  },
  authMethod: {
    type: String,
    trim: true,
    enum: ['password', 'certificate', 'key', 'token', 'unknown']
  },
  userAgent: {
    type: String,
    trim: true
  },
  geoLocation: {
    type: String,
    trim: true
  },
  riskLevel: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    default: 'LOW'
  },
  metadata: {
    type: Schema.Types.Mixed,
    default: {}
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Index for efficient querying
connectionDetailSchema.index({ connectionId: 1 });
connectionDetailSchema.index({ riskLevel: 1 });
connectionDetailSchema.index({ createdAt: -1 });

export const ConnectionDetail = mongoose.model<IConnectionDetail>('ConnectionDetail', connectionDetailSchema);