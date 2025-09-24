import mongoose, { Document, Schema } from 'mongoose';

export interface IBlockingRule extends Document {
  userId: mongoose.Types.ObjectId;
  ipAddress: string;
  port?: number;
  protocol: 'TCP' | 'UDP' | 'ALL';
  ruleType: 'IP_BLOCK' | 'PORT_BLOCK' | 'GEO_BLOCK';
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}

const blockingRuleSchema = new Schema<IBlockingRule>({
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  ipAddress: {
    type: String,
    required: true,
    trim: true,
    validate: {
      validator: function(v: string) {
        // Validate IP address or CIDR notation
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?$/;
        return ipRegex.test(v);
      },
      message: 'Invalid IP address or CIDR notation'
    }
  },
  port: {
    type: Number,
    min: 1,
    max: 65535
  },
  protocol: {
    type: String,
    enum: ['TCP', 'UDP', 'ALL'],
    default: 'ALL'
  },
  ruleType: {
    type: String,
    enum: ['IP_BLOCK', 'PORT_BLOCK', 'GEO_BLOCK'],
    required: true
  },
  enabled: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Index for efficient querying
blockingRuleSchema.index({ userId: 1, enabled: 1 });
blockingRuleSchema.index({ ipAddress: 1 });
blockingRuleSchema.index({ ruleType: 1 });

// Update the updatedAt field before saving
blockingRuleSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

export const BlockingRule = mongoose.model<IBlockingRule>('BlockingRule', blockingRuleSchema);