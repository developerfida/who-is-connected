import { Router, Request, Response } from 'express';
import { authenticate } from '../middleware/auth';
import geoIPService from '../services/geoip';
import { ConnectionLog } from '../models/ConnectionLog';

const router = Router();

/**
 * @route GET /api/geoip/lookup/:ip
 * @desc Lookup GeoIP information for a single IP address
 * @access Private
 */
router.get('/lookup/:ip', authenticate, async (req: Request, res: Response) => {
  try {
    const { ip } = req.params;
    
    // Basic IP validation
    if (!ip || !/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid IP address format'
      });
    }

    const geoData = await geoIPService.lookupIP(ip);
    
    if (!geoData) {
      return res.status(404).json({
        success: false,
        message: 'GeoIP lookup failed or no data available'
      });
    }

    res.json({
      success: true,
      data: geoData
    });
  } catch (error) {
    console.error('Error in GeoIP lookup:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during GeoIP lookup'
    });
  }
});

/**
 * @route POST /api/geoip/lookup-bulk
 * @desc Lookup GeoIP information for multiple IP addresses
 * @access Private
 */
router.post('/lookup-bulk', authenticate, async (req: Request, res: Response) => {
  try {
    const { ips } = req.body;
    
    if (!Array.isArray(ips) || ips.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid request: ips array is required'
      });
    }

    if (ips.length > 50) {
      return res.status(400).json({
        success: false,
        message: 'Too many IPs requested. Maximum 50 IPs per request.'
      });
    }

    // Validate all IPs
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const invalidIPs = ips.filter(ip => !ipRegex.test(ip));
    
    if (invalidIPs.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Invalid IP addresses: ${invalidIPs.join(', ')}`
      });
    }

    const results = await geoIPService.lookupMultipleIPs(ips);
    
    // Convert Map to object for JSON response
    const responseData: { [key: string]: any } = {};
    results.forEach((value, key) => {
      responseData[key] = value;
    });

    res.json({
      success: true,
      data: responseData
    });
  } catch (error) {
    console.error('Error in bulk GeoIP lookup:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during bulk GeoIP lookup'
    });
  }
});

/**
 * @route POST /api/geoip/update-connections
 * @desc Update existing connections with GeoIP data
 * @access Private
 */
router.post('/update-connections', authenticate, async (req: Request, res: Response) => {
  try {
    const { limit = 100 } = req.body;
    
    // Find connections without GeoIP data
    const connections = await ConnectionLog.find({
      $or: [
        { geoLocation: { $exists: false } },
        { 'geoLocation.status': { $exists: false } }
      ]
    })
    .limit(limit)
    .select('_id remoteIP geoLocation');

    if (connections.length === 0) {
      return res.json({
        success: true,
        message: 'No connections need GeoIP updates',
        updated: 0
      });
    }

    let updated = 0;
    const errors: string[] = [];

    for (const connection of connections) {
      try {
        const geoData = await geoIPService.lookupIP(connection.remoteIP);
        
        if (geoData) {
          await ConnectionLog.findByIdAndUpdate(connection._id, {
            geoLocation: geoData
          });
          updated++;
        }
      } catch (error) {
        errors.push(`Failed to update ${connection.remoteIP}: ${error}`);
      }
    }

    res.json({
      success: true,
      message: `Updated ${updated} connections with GeoIP data`,
      updated,
      total: connections.length,
      errors: errors.length > 0 ? errors : undefined
    });
  } catch (error) {
    console.error('Error updating connections with GeoIP:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during GeoIP update'
    });
  }
});

/**
 * @route GET /api/geoip/stats
 * @desc Get GeoIP service statistics
 * @access Private
 */
router.get('/stats', authenticate, async (req: Request, res: Response) => {
  try {
    const cacheStats = geoIPService.getCacheStats();
    
    // Get connection statistics by country
    const countryStats = await ConnectionLog.aggregate([
      {
        $match: {
          'geoLocation.countryCode': { $exists: true, $ne: null }
        }
      },
      {
        $group: {
          _id: '$geoLocation.countryCode',
          country: { $first: '$geoLocation.country' },
          count: { $sum: 1 },
          activeCount: {
            $sum: {
              $cond: [{ $eq: ['$status', 'active'] }, 1, 0]
            }
          }
        }
      },
      {
        $sort: { count: -1 }
      },
      {
        $limit: 20
      }
    ]);

    res.json({
      success: true,
      data: {
        cache: cacheStats,
        topCountries: countryStats
      }
    });
  } catch (error) {
    console.error('Error getting GeoIP stats:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error getting GeoIP stats'
    });
  }
});

/**
 * @route DELETE /api/geoip/cache
 * @desc Clear GeoIP cache
 * @access Private
 */
router.delete('/cache', authenticate, async (req: Request, res: Response) => {
  try {
    geoIPService.clearCache();
    
    res.json({
      success: true,
      message: 'GeoIP cache cleared successfully'
    });
  } catch (error) {
    console.error('Error clearing GeoIP cache:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error clearing cache'
    });
  }
});

/**
 * @route GET /api/geoip/suspicious-countries
 * @desc Get list of connections from suspicious countries
 * @access Private
 */
router.get('/suspicious-countries', authenticate, async (req: Request, res: Response) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (Number(page) - 1) * Number(limit);

    // Get all suspicious country codes
    const suspiciousCountries = ['CN', 'RU', 'KP', 'IR', 'SY', 'CU', 'SD'];
    
    const connections = await ConnectionLog.find({
      'geoLocation.countryCode': { $in: suspiciousCountries }
    })
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(Number(limit))
    .populate('userId', 'username')
    .lean();

    const total = await ConnectionLog.countDocuments({
      'geoLocation.countryCode': { $in: suspiciousCountries }
    });

    res.json({
      success: true,
      data: {
        connections,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit))
        }
      }
    });
  } catch (error) {
    console.error('Error getting suspicious country connections:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error getting suspicious connections'
    });
  }
});

export default router;