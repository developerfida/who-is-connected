/**
 * Settings API routes
 * Handle blocking rules, alert configurations, and monitoring preferences
 */
import { Router, type Response } from 'express';
import Joi from 'joi';
import { BlockingRule, AlertConfig, SecurityAlert } from '../models';
import { authenticate, requireAdmin, AuthRequest } from '../middleware/auth';

const router = Router();

// Validation schemas
const blockingRuleSchema = Joi.object({
  ipAddress: Joi.string().required(),
  port: Joi.number().integer().min(1).max(65535),
  protocol: Joi.string().valid('TCP', 'UDP', 'ALL').default('ALL'),
  ruleType: Joi.string().valid('IP_BLOCK', 'PORT_BLOCK', 'GEO_BLOCK').required(),
  enabled: Joi.boolean().default(true)
});

const alertConfigSchema = Joi.object({
  alertType: Joi.string().valid(
    'SUSPICIOUS_CONNECTION',
    'MULTIPLE_ATTEMPTS',
    'UNAUTHORIZED_ACCESS',
    'HIGH_RISK_IP',
    'UNUSUAL_ACTIVITY',
    'BLOCKED_CONNECTION'
  ).required(),
  emailEnabled: Joi.boolean().default(false),
  desktopEnabled: Joi.boolean().default(true),
  thresholds: Joi.object({
    maxConnections: Joi.number().integer().min(1),
    maxAttempts: Joi.number().integer().min(1),
    timeWindow: Joi.number().integer().min(60), // seconds
    riskLevel: Joi.string().valid('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
  }).default({})
});

// ============ BLOCKING RULES ============

/**
 * Get All Blocking Rules
 * GET /api/settings/blocking-rules
 */
router.get('/blocking-rules', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const userId = req.user?._id;
    
    const rules = await BlockingRule.find({ userId })
      .sort({ createdAt: -1 })
      .populate('userId', 'username');

    const stats = {
      total: rules.length,
      enabled: rules.filter(rule => rule.enabled).length,
      disabled: rules.filter(rule => !rule.enabled).length,
      byType: {} as Record<string, number>
    };

    rules.forEach(rule => {
      stats.byType[rule.ruleType] = (stats.byType[rule.ruleType] || 0) + 1;
    });

    res.json({
      success: true,
      rules,
      stats
    });
  } catch (error) {
    console.error('Error fetching blocking rules:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while fetching blocking rules'
    });
  }
});

/**
 * Create Blocking Rule
 * POST /api/settings/blocking-rules
 */
router.post('/blocking-rules', authenticate, requireAdmin, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const { error, value } = blockingRuleSchema.validate(req.body);
    if (error) {
      res.status(400).json({
        success: false,
        message: 'Validation error',
        details: error.details[0].message
      });
      return;
    }

    const userId = req.user?._id;
    const { ipAddress, port, protocol, ruleType, enabled } = value;

    // Check for duplicate rules
    const existingRule = await BlockingRule.findOne({
      userId,
      ipAddress,
      port: port || null,
      protocol,
      ruleType
    });

    if (existingRule) {
      res.status(409).json({
        success: false,
        message: 'A similar blocking rule already exists'
      });
      return;
    }

    const rule = new BlockingRule({
      userId,
      ipAddress,
      port,
      protocol,
      ruleType,
      enabled
    });

    await rule.save();

    // Create security alert for new blocking rule
    const alert = new SecurityAlert({
      alertType: 'BLOCKING_RULE_CREATED',
      severity: 'MEDIUM',
      message: `New blocking rule created for ${ipAddress} by ${req.user?.username}`,
      acknowledged: false
    });
    await alert.save();

    res.status(201).json({
      success: true,
      message: 'Blocking rule created successfully',
      rule
    });
  } catch (error) {
    console.error('Error creating blocking rule:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while creating blocking rule'
    });
  }
});

/**
 * Update Blocking Rule
 * PUT /api/settings/blocking-rules/:id
 */
router.put('/blocking-rules/:id', authenticate, requireAdmin, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const { error, value } = blockingRuleSchema.validate(req.body);
    if (error) {
      res.status(400).json({
        success: false,
        message: 'Validation error',
        details: error.details[0].message
      });
      return;
    }

    const ruleId = req.params.id;
    const userId = req.user?._id;

    const rule = await BlockingRule.findOne({ _id: ruleId, userId });
    if (!rule) {
      res.status(404).json({
        success: false,
        message: 'Blocking rule not found'
      });
      return;
    }

    // Update rule
    Object.assign(rule, value);
    rule.updatedAt = new Date();
    await rule.save();

    res.json({
      success: true,
      message: 'Blocking rule updated successfully',
      rule
    });
  } catch (error) {
    console.error('Error updating blocking rule:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while updating blocking rule'
    });
  }
});

/**
 * Delete Blocking Rule
 * DELETE /api/settings/blocking-rules/:id
 */
router.delete('/blocking-rules/:id', authenticate, requireAdmin, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const ruleId = req.params.id;
    const userId = req.user?._id;

    const rule = await BlockingRule.findOneAndDelete({ _id: ruleId, userId });
    if (!rule) {
      res.status(404).json({
        success: false,
        message: 'Blocking rule not found'
      });
      return;
    }

    res.json({
      success: true,
      message: 'Blocking rule deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting blocking rule:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while deleting blocking rule'
    });
  }
});

// ============ ALERT CONFIGURATIONS ============

/**
 * Get Alert Configurations
 * GET /api/settings/alert-configs
 */
router.get('/alert-configs', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const userId = req.user?._id;
    
    const configs = await AlertConfig.find({ userId })
      .sort({ alertType: 1 });

    res.json({
      success: true,
      configs
    });
  } catch (error) {
    console.error('Error fetching alert configurations:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while fetching alert configurations'
    });
  }
});

/**
 * Create or Update Alert Configuration
 * POST /api/settings/alert-configs
 */
router.post('/alert-configs', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const { error, value } = alertConfigSchema.validate(req.body);
    if (error) {
      res.status(400).json({
        success: false,
        message: 'Validation error',
        details: error.details[0].message
      });
      return;
    }

    const userId = req.user?._id;
    const { alertType, emailEnabled, desktopEnabled, thresholds } = value;

    // Check if configuration already exists
    let config = await AlertConfig.findOne({ userId, alertType });
    
    if (config) {
      // Update existing configuration
      config.emailEnabled = emailEnabled;
      config.desktopEnabled = desktopEnabled;
      config.thresholds = { ...config.thresholds, ...thresholds };
      await config.save();

      res.json({
        success: true,
        message: 'Alert configuration updated successfully',
        config
      });
    } else {
      // Create new configuration
      config = new AlertConfig({
        userId,
        alertType,
        emailEnabled,
        desktopEnabled,
        thresholds
      });
      await config.save();

      res.status(201).json({
        success: true,
        message: 'Alert configuration created successfully',
        config
      });
    }
  } catch (error) {
    console.error('Error saving alert configuration:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while saving alert configuration'
    });
  }
});

/**
 * Delete Alert Configuration
 * DELETE /api/settings/alert-configs/:alertType
 */
router.delete('/alert-configs/:alertType', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const alertType = req.params.alertType;
    const userId = req.user?._id;

    const config = await AlertConfig.findOneAndDelete({ userId, alertType });
    if (!config) {
      res.status(404).json({
        success: false,
        message: 'Alert configuration not found'
      });
      return;
    }

    res.json({
      success: true,
      message: 'Alert configuration deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting alert configuration:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while deleting alert configuration'
    });
  }
});

// ============ SECURITY ALERTS ============

/**
 * Get Security Alerts
 * GET /api/settings/alerts
 */
router.get('/alerts', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 1000; // Changed default from 20 to 1000
    const severity = req.query.severity as string;
    const acknowledged = req.query.acknowledged === 'true';
    const hours = parseInt(req.query.hours as string); // New parameter for time-based filtering

    const query: any = {};
    if (severity) query.severity = severity;
    
    // Special handling for CRITICAL alerts with time-based filtering
    if (severity === 'CRITICAL' && hours) {
      // For CRITICAL alerts, show all alerts from the last X hours regardless of acknowledgment
      const hoursAgo = new Date(Date.now() - (hours * 60 * 60 * 1000));
      query.createdAt = { $gte: hoursAgo };
      // Don't filter by acknowledged status for CRITICAL alerts within time window
    } else {
      // Only filter by acknowledged status if explicitly requested (not 'all')
      if (req.query.acknowledged !== undefined && req.query.acknowledged !== 'all') {
        query.acknowledged = acknowledged;
      }
    }

    const total = await SecurityAlert.countDocuments(query);
    const alerts = await SecurityAlert.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .populate('connectionId', 'remoteIP remotePort connectionType');

    res.json({
      success: true,
      alerts,
      total, // Add total count at root level for frontend stats
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching security alerts:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while fetching security alerts'
    });
  }
});

/**
 * Acknowledge Security Alert
 * POST /api/settings/alerts/:id/acknowledge
 */
router.post('/alerts/:id/acknowledge', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const alertId = req.params.id;

    const alert = await SecurityAlert.findById(alertId);
    if (!alert) {
      res.status(404).json({
        success: false,
        message: 'Security alert not found'
      });
      return;
    }

    alert.acknowledged = true;
    await alert.save();

    res.json({
      success: true,
      message: 'Security alert acknowledged successfully',
      alert
    });
  } catch (error) {
    console.error('Error acknowledging security alert:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while acknowledging alert'
    });
  }
});

/**
 * Bulk Acknowledge Security Alerts
 * POST /api/settings/alerts/acknowledge-all
 */
router.post('/alerts/acknowledge-all', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const severity = req.body.severity as string;
    const query: any = { acknowledged: false };
    
    if (severity) {
      query.severity = severity;
    }

    const result = await SecurityAlert.updateMany(query, { acknowledged: true });

    res.json({
      success: true,
      message: `${result.modifiedCount} security alerts acknowledged successfully`,
      modifiedCount: result.modifiedCount
    });
  } catch (error) {
    console.error('Error bulk acknowledging security alerts:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while bulk acknowledging alerts'
    });
  }
});

export default router;