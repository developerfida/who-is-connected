// GeoIP utility functions

// Interface for GeoIP data
export interface GeoLocation {
  country?: string;
  countryCode?: string;
  city?: string;
  region?: string;
  isp?: string;
  asn?: string;
  lat?: number;
  lon?: number;
  timezone?: string;
}

// Get country flag emoji from country code
export const getCountryFlag = (countryCode?: string): string => {
  if (!countryCode || countryCode.length !== 2) {
    return '🌍'; // Default globe emoji
  }
  
  // Convert country code to flag emoji
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0));
  
  return String.fromCodePoint(...codePoints);
};

// Format location string
export const formatLocation = (geoLocation?: GeoLocation): string => {
  if (!geoLocation) return 'Unknown';
  
  const parts: string[] = [];
  
  if (geoLocation.city) {
    parts.push(geoLocation.city);
  }
  
  if (geoLocation.region && geoLocation.region !== geoLocation.city) {
    parts.push(geoLocation.region);
  }
  
  if (geoLocation.country) {
    parts.push(geoLocation.country);
  }
  
  return parts.length > 0 ? parts.join(', ') : 'Unknown';
};

// Format ISP/ASN information
export const formatISP = (geoLocation?: GeoLocation): string => {
  if (!geoLocation) return 'Unknown';
  
  const parts: string[] = [];
  
  if (geoLocation.isp) {
    parts.push(geoLocation.isp);
  }
  
  if (geoLocation.asn) {
    parts.push(`(${geoLocation.asn})`);
  }
  
  return parts.length > 0 ? parts.join(' ') : 'Unknown';
};

// Check if country is suspicious (based on common threat countries)
export const isSuspiciousCountry = (countryCode?: string): boolean => {
  if (!countryCode) return false;
  
  const suspiciousCountries = [
    'CN', 'RU', 'KP', 'IR', 'SY', 'AF', 'IQ', 'LY', 'SO', 'SD',
    'YE', 'MM', 'BY', 'VE', 'CU', 'ER', 'TD', 'CF', 'SS', 'ML'
  ];
  
  return suspiciousCountries.includes(countryCode.toUpperCase());
};

// Get risk level based on country
export const getCountryRiskLevel = (countryCode?: string): 'low' | 'medium' | 'high' => {
  if (!countryCode) return 'medium';
  
  if (isSuspiciousCountry(countryCode)) {
    return 'high';
  }
  
  // Medium risk countries (some known for cyber activities but not as severe)
  const mediumRiskCountries = ['PK', 'BD', 'VN', 'IN', 'ID', 'PH', 'TH', 'MY'];
  
  if (mediumRiskCountries.includes(countryCode.toUpperCase())) {
    return 'medium';
  }
  
  return 'low';
};

// Get risk color for UI display
export const getRiskColor = (riskLevel: 'low' | 'medium' | 'high'): string => {
  switch (riskLevel) {
    case 'high':
      return 'text-red-600 dark:text-red-400';
    case 'medium':
      return 'text-yellow-600 dark:text-yellow-400';
    case 'low':
    default:
      return 'text-green-600 dark:text-green-400';
  }
};

// Get risk background color for badges
export const getRiskBgColor = (riskLevel: 'low' | 'medium' | 'high'): string => {
  switch (riskLevel) {
    case 'high':
      return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
    case 'medium':
      return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200';
    case 'low':
    default:
      return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200';
  }
};