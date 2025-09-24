import { IGeoLocation } from '../models/ConnectionLog';

// Simple in-memory cache for GeoIP lookups
interface GeoIPCache {
  [ip: string]: {
    data: IGeoLocation;
    timestamp: number;
    ttl: number;
  };
}

class GeoIPService {
  private cache: GeoIPCache = {};
  private readonly CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
  private readonly API_BASE_URL = 'http://ip-api.com/json';
  private readonly RATE_LIMIT_DELAY = 1000; // 1 second between requests
  private lastRequestTime = 0;

  /**
   * Clean expired cache entries
   */
  private cleanCache(): void {
    const now = Date.now();
    Object.keys(this.cache).forEach(ip => {
      const entry = this.cache[ip];
      if (now - entry.timestamp > entry.ttl) {
        delete this.cache[ip];
      }
    });
  }

  /**
   * Check if IP is private/local and should not be looked up
   */
  private isPrivateIP(ip: string): boolean {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(part => isNaN(part) || part < 0 || part > 255)) {
      return true; // Invalid IP, treat as private
    }

    // Private IP ranges:
    // 10.0.0.0 - 10.255.255.255
    // 172.16.0.0 - 172.31.255.255
    // 192.168.0.0 - 192.168.255.255
    // 127.0.0.0 - 127.255.255.255 (loopback)
    return (
      parts[0] === 10 ||
      parts[0] === 127 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168)
    );
  }

  /**
   * Rate limiting - ensure we don't exceed API limits
   */
  private async rateLimit(): Promise<void> {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;
    
    if (timeSinceLastRequest < this.RATE_LIMIT_DELAY) {
      const delay = this.RATE_LIMIT_DELAY - timeSinceLastRequest;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
    
    this.lastRequestTime = Date.now();
  }

  /**
   * Lookup GeoIP information for an IP address
   */
  async lookupIP(ip: string): Promise<IGeoLocation | null> {
    try {
      // Clean cache periodically
      this.cleanCache();

      // Check if IP is private/local
      if (this.isPrivateIP(ip)) {
        return {
          country: 'Local',
          countryCode: 'LOCAL',
          city: 'Local Network',
          region: 'N/A',
          regionName: 'Local Network',
          isp: 'Local Network',
          org: 'Private Network',
          asn: 'N/A',
          query: ip,
          status: 'private'
        };
      }

      // Check cache first
      const cached = this.cache[ip];
      if (cached && (Date.now() - cached.timestamp) < cached.ttl) {
        return cached.data;
      }

      // Rate limiting
      await this.rateLimit();

      // Make API request
      const response = await fetch(`${this.API_BASE_URL}/${ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query`);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();

      // Check if API returned success
      if (data.status !== 'success') {
        console.warn(`GeoIP lookup failed for ${ip}: ${data.message || 'Unknown error'}`);
        return null;
      }

      // Transform API response to our format
      const geoData: IGeoLocation = {
        country: data.country || 'Unknown',
        countryCode: data.countryCode || 'XX',
        city: data.city || 'Unknown',
        region: data.region || 'Unknown',
        regionName: data.regionName || 'Unknown',
        isp: data.isp || 'Unknown',
        org: data.org || 'Unknown',
        asn: data.as || 'Unknown',
        timezone: data.timezone || 'Unknown',
        lat: data.lat || 0,
        lon: data.lon || 0,
        query: data.query || ip,
        status: 'success'
      };

      // Cache the result
      this.cache[ip] = {
        data: geoData,
        timestamp: Date.now(),
        ttl: this.CACHE_TTL
      };

      return geoData;

    } catch (error) {
      console.error(`Error looking up GeoIP for ${ip}:`, error);
      return null;
    }
  }

  /**
   * Bulk lookup multiple IPs (with rate limiting)
   */
  async lookupMultipleIPs(ips: string[]): Promise<Map<string, IGeoLocation | null>> {
    const results = new Map<string, IGeoLocation | null>();
    
    for (const ip of ips) {
      const result = await this.lookupIP(ip);
      results.set(ip, result);
    }
    
    return results;
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; entries: string[] } {
    this.cleanCache();
    return {
      size: Object.keys(this.cache).length,
      entries: Object.keys(this.cache)
    };
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.cache = {};
  }

  /**
   * Check if a country is considered suspicious
   */
  isSuspiciousCountry(countryCode: string): boolean {
    // List of countries that might be considered higher risk
    // This is configurable and should be based on organization's security policy
    const suspiciousCountries = [
      'CN', // China
      'RU', // Russia
      'KP', // North Korea
      'IR', // Iran
      'SY', // Syria
      'CU', // Cuba
      'SD', // Sudan
    ];
    
    return suspiciousCountries.includes(countryCode?.toUpperCase());
  }

  /**
   * Get country flag emoji from country code
   */
  getCountryFlag(countryCode: string): string {
    if (!countryCode || countryCode === 'LOCAL' || countryCode === 'XX') {
      return '🏠'; // House emoji for local/unknown
    }
    
    // Convert country code to flag emoji
    // Each country code letter corresponds to a regional indicator symbol
    const codePoints = countryCode
      .toUpperCase()
      .split('')
      .map(char => 127397 + char.charCodeAt(0));
    
    return String.fromCodePoint(...codePoints);
  }
}

// Export singleton instance
export const geoIPService = new GeoIPService();
export default geoIPService;