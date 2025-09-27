/**
 * Utility functions for extracting IP addresses from alert messages
 */

// Regular expression to match IPv4 addresses
const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;

// Regular expression to match IPv6 addresses (basic pattern)
const IPV6_REGEX = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|\b::1\b|\b::ffff:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b/gi;

/**
 * Extracts the first IP address found in a text message
 * @param message - The alert message to search for IP addresses
 * @returns The first IP address found, or null if none found
 */
export function extractIPFromMessage(message: string): string | null {
  if (!message) return null;

  // First try to find IPv4 addresses
  const ipv4Matches = message.match(IPV4_REGEX);
  if (ipv4Matches && ipv4Matches.length > 0) {
    return ipv4Matches[0];
  }

  // Then try to find IPv6 addresses
  const ipv6Matches = message.match(IPV6_REGEX);
  if (ipv6Matches && ipv6Matches.length > 0) {
    return ipv6Matches[0];
  }

  return null;
}

/**
 * Extracts all IP addresses found in a text message
 * @param message - The alert message to search for IP addresses
 * @returns Array of all IP addresses found
 */
export function extractAllIPsFromMessage(message: string): string[] {
  if (!message) return [];

  const ips: string[] = [];

  // Find all IPv4 addresses
  const ipv4Matches = message.match(IPV4_REGEX);
  if (ipv4Matches) {
    ips.push(...ipv4Matches);
  }

  // Find all IPv6 addresses
  const ipv6Matches = message.match(IPV6_REGEX);
  if (ipv6Matches) {
    ips.push(...ipv6Matches);
  }

  // Remove duplicates
  return [...new Set(ips)];
}

/**
 * Gets the display IP address for a security alert
 * Priority: connectionId.remoteIP > extracted from message > 'N/A'
 * @param alert - The security alert object
 * @returns The IP address to display
 */
export function getDisplayIP(alert: any): string {
  // First priority: use connectionId.remoteIP if available
  if (alert.connectionId?.remoteIP) {
    return alert.connectionId.remoteIP;
  }

  // Second priority: extract IP from message
  const extractedIP = extractIPFromMessage(alert.message);
  if (extractedIP) {
    return extractedIP;
  }

  // Default: show N/A
  return 'N/A';
}

/**
 * Validates if a string is a valid IP address
 * @param ip - The IP address string to validate
 * @returns True if valid IP address, false otherwise
 */
export function isValidIP(ip: string): boolean {
  if (!ip) return false;

  // Check IPv4
  const ipv4Match = ip.match(/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/);
  if (ipv4Match) return true;

  // Check IPv6 (basic validation)
  const ipv6Match = ip.match(/^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$|^:(?::[0-9a-fA-F]{1,4}){1,7}$|^::1$|^::ffff:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/i);
  if (ipv6Match) return true;

  return false;
}