#!/usr/bin/env python3
"""
Test script to simulate security threats and verify alert generation
"""

import requests
import json
import time
from datetime import datetime

# Configuration
API_BASE_URL = "http://localhost:3001/api"
PYTHON_API_KEY = "python-monitor-key-change-in-production"

def send_security_alert(alert_type, severity, message, connection_id=None):
    """Send a security alert to the API"""
    url = f"{API_BASE_URL}/python/security/alert"
    headers = {
        'Content-Type': 'application/json',
        'X-API-Key': PYTHON_API_KEY
    }
    
    data = {
        'alert_type': alert_type,
        'severity': severity,
        'message': message,
        'connection_id': connection_id
    }
    
    try:
        response = requests.post(url, json=data, headers=headers, timeout=10)
        response.raise_for_status()
        print(f"✅ Alert sent: {severity} - {alert_type} - {message[:50]}...")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to send alert: {e}")
        return None

def test_multiple_attempts_alerts():
    """Test multiple connection attempts alerts"""
    print("\n🔥 Testing MULTIPLE_ATTEMPTS alerts...")
    
    # Test CRITICAL alert (6+ attempts)
    send_security_alert(
        'MULTIPLE_ATTEMPTS',
        'CRITICAL',
        'CRITICAL: Multiple connection attempts (8) from 3.233.158.26 in the last 5 minutes - Possible brute force attack'
    )
    
    time.sleep(1)
    
    # Test HIGH alert (4-5 attempts)
    send_security_alert(
        'MULTIPLE_ATTEMPTS',
        'HIGH',
        'Multiple connection attempts (4) from 192.168.1.100 in the last 5 minutes'
    )
    
    time.sleep(1)
    
    # Test MEDIUM alert (2-3 attempts)
    send_security_alert(
        'MULTIPLE_ATTEMPTS',
        'MEDIUM',
        'Multiple connection attempts (3) from 10.0.0.50 detected'
    )

def test_country_based_alerts():
    """Test country-based security alerts"""
    print("\n🌍 Testing country-based alerts...")
    
    # Test CRITICAL country threat
    send_security_alert(
        'SUSPICIOUS_COUNTRY',
        'CRITICAL',
        'CRITICAL: Connection from high-threat country North Korea (KP) detected from 175.45.176.1 - State-sponsored threat risk'
    )
    
    time.sleep(1)
    
    # Test HIGH risk country
    send_security_alert(
        'SUSPICIOUS_COUNTRY',
        'HIGH',
        'Connection from high-risk country China (CN) detected from 123.45.67.89'
    )

def test_suspicious_activity_alerts():
    """Test various suspicious activity alerts"""
    print("\n⚠️  Testing suspicious activity alerts...")
    
    # Test suspicious port
    send_security_alert(
        'SUSPICIOUS_PORT',
        'MEDIUM',
        'Connection from suspicious port 31337 detected from 198.51.100.42'
    )
    
    time.sleep(1)
    
    # Test unusual activity
    send_security_alert(
        'UNUSUAL_ACTIVITY',
        'MEDIUM',
        'Non-RDP connection on RDP port 3389 from 203.0.113.15 (Type: HTTP)'
    )
    
    time.sleep(1)
    
    # Test system breach attempt
    send_security_alert(
        'SYSTEM_BREACH_ATTEMPT',
        'CRITICAL',
        'CRITICAL: Potential system breach attempt detected - Multiple failed authentication attempts with privilege escalation'
    )

def main():
    """Main test function"""
    print("🚨 Security Alert Pipeline Test")
    print("=" * 40)
    print(f"API Base URL: {API_BASE_URL}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    
    # Test different types of alerts
    test_multiple_attempts_alerts()
    test_country_based_alerts()
    test_suspicious_activity_alerts()
    
    print("\n✅ All test alerts sent!")
    print("\n📋 Check the following to verify the alert pipeline:")
    print("1. Backend logs should show alert processing")
    print("2. Dashboard should display new alerts with proper colors")
    print("3. System Monitor should show all alerts in history")
    print("4. WebSocket should broadcast alerts in real-time")
    print("\n🔍 Expected alert colors:")
    print("   - CRITICAL: Red background/text")
    print("   - HIGH: Orange background/text")
    print("   - MEDIUM: Yellow background/text")

if __name__ == "__main__":
    main()