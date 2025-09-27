#!/usr/bin/env python3
"""
Windows Remote Connection Monitor
Detects and monitors all remote connections to the Windows system
"""

import asyncio
import json
import logging
import os
import socket
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import re

import psutil
import requests
try:
    import win32api
    import win32con
    import win32security
    import win32service
    import wmi
except ImportError:
    # Redirect warning to stderr instead of stdout to avoid JSON parsing issues
    import sys
    print("Warning: pywin32 not available. Some Windows-specific features will be disabled.", file=sys.stderr)
    win32api = win32con = win32security = win32service = wmi = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('connection_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class WindowsConnectionMonitor:
    """Monitor remote connections on Windows systems"""
    
    def __init__(self, api_base_url: str = "http://localhost:3001/api", poll_interval: int = 5):
        self.api_base_url = api_base_url
        self.poll_interval = poll_interval
        self.known_connections = set()
        self.wmi_conn = None
        
        # Initialize WMI connection if available
        if wmi:
            try:
                self.wmi_conn = wmi.WMI()
                logger.info("WMI connection established")
            except Exception as e:
                logger.warning(f"Failed to establish WMI connection: {e}")
        
        # Security lists for suspicious domain detection
        self.suspicious_domains = {
            'malware', 'phishing', 'suspicious', 'malicious', 'hack', 'exploit',
            'trojan', 'virus', 'spam', 'scam', 'fraud', 'fake', 'illegal',
            'darkweb', 'tor', 'onion', 'bitcoin', 'crypto-mining'
        }
        
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.onion', '.bit'
        }
        
        # Patterns for suspicious URLs
        self.suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'[a-z0-9]{20,}\.',  # Long random subdomains
            r'\b(download|install|update|security|alert|warning)\b.*\.(exe|zip|rar)',
            r'\b(free|crack|keygen|serial|patch)\b'
        ]
        
        # GeoIP cache and settings
        self.geoip_cache = {}
        self.geoip_cache_ttl = 24 * 60 * 60  # 24 hours in seconds
        self.geoip_api_url = 'http://ip-api.com/json'
        self.last_geoip_request = 0
        self.geoip_rate_limit = 1.0  # 1 second between requests
    
    def get_network_connections(self) -> List[Dict]:
        """Get all network connections using psutil"""
        connections = []
        
        try:
            # Get all network connections
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    # Classify connection direction and type
                    direction = self._get_connection_direction(conn)
                    connection_type = self._identify_connection_type(conn)
                    
                    # Include both inbound remote connections and outbound browser connections
                    if direction == 'inbound' or self._is_browser_connection(conn):
                        process_name = self._get_process_name(conn.pid)
                        domain = self._extract_domain(conn.raddr.ip) if direction == 'outbound' else None
                        
                        # Perform GeoIP lookup for the remote IP
                        geo_data = self.lookup_geoip(conn.raddr.ip)
                        
                        # Create connection info with only fields expected by backend API
                        connection_info = {
                            'local_ip': conn.laddr.ip if conn.laddr else '0.0.0.0',
                            'local_port': conn.laddr.port if conn.laddr else 0,
                            'remote_ip': conn.raddr.ip,
                            'remote_port': conn.raddr.port,
                            'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                            'connection_type': connection_type,
                            'direction': direction,
                            'process_name': process_name or '',
                            'pid': conn.pid or 0,
                            'username': self._get_connection_user(conn.pid) or '',
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        # Add GeoIP data if available
                        if geo_data:
                            connection_info['geoLocation'] = geo_data
                        
                        connections.append(connection_info)
        
        except Exception as e:
            logger.error(f"Error getting network connections: {e}")
        
        return connections
    
    def _get_connection_direction(self, conn) -> str:
        """Determine if a connection is inbound or outbound"""
        if not conn.raddr:
            return 'unknown'
        
        # Check if the remote IP is external (not local network)
        remote_ip = conn.raddr.ip
        
        # Skip localhost connections
        if remote_ip in ['127.0.0.1', '::1']:
            return 'local'
        
        # Check for common remote access ports (inbound)
        local_port = conn.laddr.port if conn.laddr else None
        remote_access_ports = [3389, 22, 5900, 5901, 5938, 5985, 5986]
        
        if local_port in remote_access_ports:
            return 'inbound'
        
        # Check if it's an inbound connection by examining the process
        process_name = self._get_process_name(conn.pid)
        remote_processes = ['svchost.exe', 'winlogon.exe', 'rdpclip.exe', 'dwm.exe']
        
        if any(proc in process_name.lower() for proc in remote_processes):
            return 'inbound'
        
        # Most other connections are outbound
        return 'outbound'
    
    def _is_browser_connection(self, conn) -> bool:
        """Determine if a connection is from a browser process"""
        if not conn.raddr:
            return False
        
        process_name = self._get_process_name(conn.pid).lower()
        browser_processes = [
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe',
            'opera.exe', 'brave.exe', 'vivaldi.exe', 'safari.exe'
        ]
        
        # Check if it's a browser process
        is_browser = any(browser in process_name for browser in browser_processes)
        
        # Check if it's HTTP/HTTPS traffic
        remote_port = conn.raddr.port
        is_web_traffic = remote_port in [80, 443, 8080, 8443]
        
        return is_browser and is_web_traffic
    
    def _get_browser_type(self, process_name: str) -> Optional[str]:
        """Identify the browser type from process name"""
        process_name = process_name.lower()
        
        if 'chrome.exe' in process_name:
            return 'Chrome'
        elif 'firefox.exe' in process_name:
            return 'Firefox'
        elif 'msedge.exe' in process_name:
            return 'Edge'
        elif 'iexplore.exe' in process_name:
            return 'Internet Explorer'
        elif 'opera.exe' in process_name:
            return 'Opera'
        elif 'brave.exe' in process_name:
            return 'Brave'
        elif 'vivaldi.exe' in process_name:
            return 'Vivaldi'
        elif 'safari.exe' in process_name:
            return 'Safari'
        
        return None
    
    def _extract_domain(self, ip_address: str) -> Optional[str]:
        """Extract domain name from IP address using reverse DNS lookup"""
        try:
            domain = socket.gethostbyaddr(ip_address)[0]
            return domain
        except (socket.herror, socket.gaierror):
            # If reverse DNS fails, return the IP address
            return ip_address
    
    def _is_suspicious_connection(self, domain: str, connection_type: str, direction: str) -> bool:
        """Determine if a connection is suspicious based on various factors"""
        if not domain:
            return False
        
        domain_lower = domain.lower()
        
        # Check for suspicious domain keywords
        for suspicious_word in self.suspicious_domains:
            if suspicious_word in domain_lower:
                return True
        
        # Check for suspicious TLDs
        for tld in self.suspicious_tlds:
            if domain_lower.endswith(tld):
                return True
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, domain_lower):
                return True
        
        # Check for direct IP connections (potentially suspicious)
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            return True
        
        # Check for very short or very long domain names
        if len(domain) < 4 or len(domain) > 50:
            return True
        
        return False
    
    def _assess_security_risk(self, domain: str, connection_type: str, direction: str) -> str:
        """Assess the security risk level of a connection"""
        risk_score = 0
        
        if not domain:
            return 'LOW'
        
        domain_lower = domain.lower()
        
        # High risk indicators
        high_risk_keywords = {'malware', 'phishing', 'trojan', 'virus', 'hack', 'exploit'}
        for keyword in high_risk_keywords:
            if keyword in domain_lower:
                risk_score += 3
        
        # Medium risk indicators
        medium_risk_keywords = {'suspicious', 'fake', 'scam', 'fraud', 'illegal'}
        for keyword in medium_risk_keywords:
            if keyword in domain_lower:
                risk_score += 2
        
        # Check for suspicious TLDs
        for tld in self.suspicious_tlds:
            if domain_lower.endswith(tld):
                risk_score += 2
        
        # Direct IP connections are medium risk
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            risk_score += 1
        
        # Inbound connections to non-standard ports are higher risk
        if direction == 'inbound' and connection_type not in ['RDP', 'SSH', 'VNC']:
            risk_score += 1
        
        # Determine risk level
        if risk_score >= 3:
            return 'HIGH'
        elif risk_score >= 1:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_process_name(self, pid: Optional[int]) -> str:
        """Get process name from PID"""
        if not pid:
            return "Unknown"
        
        try:
            process = psutil.Process(pid)
            return process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "Unknown"
    
    def _identify_connection_type(self, conn) -> str:
        """Identify the type of connection"""
        local_port = conn.laddr.port if conn.laddr else None
        remote_port = conn.raddr.port if conn.raddr else None
        process_name = self._get_process_name(conn.pid).lower()
        
        # RDP connections (Remote Desktop Protocol)
        if local_port == 3389 or remote_port == 3389 or 'rdp' in process_name or 'mstsc' in process_name or 'termsrv' in process_name:
            return 'RDP'
        
        # SSH connections (Secure Shell)
        if local_port == 22 or remote_port == 22 or 'ssh' in process_name or 'putty' in process_name or 'openssh' in process_name:
            return 'SSH'
        
        # VNC connections (Virtual Network Computing) - ports 5900-5999
        if ((local_port and 5900 <= local_port <= 5999) or 
            (remote_port and 5900 <= remote_port <= 5999) or 
            'vnc' in process_name or 'tightvnc' in process_name or 'realvnc' in process_name or 'ultravnc' in process_name):
            return 'VNC'
        
        # TeamViewer connections
        if (local_port == 5938 or remote_port == 5938 or 
            'teamviewer' in process_name or 
            (remote_port and remote_port in [5938, 443]) and 'teamviewer' in process_name):
            return 'TeamViewer'
        
        # HTTP connections (port 80)
        if remote_port == 80:
            return 'HTTP'
        
        # HTTPS connections (port 443)
        if remote_port == 443:
            return 'HTTPS'
        
        # WebSocket connections (common ports and process indicators)
        if remote_port in [8080, 8443, 3000, 3001, 5000] or 'websocket' in process_name or 'ws' in process_name:
            return 'WebSocket'
        
        # Browser connections on non-standard ports
        browser_processes = ['chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe', 'opera.exe', 'brave.exe']
        if any(browser in process_name for browser in browser_processes):
            if remote_port == 443:
                return 'HTTPS'
            elif remote_port == 80:
                return 'HTTP'
            else:
                return 'HTTPS'  # Assume HTTPS for other browser connections
        
        # All other connections
        return 'Other'
    
    def _get_connection_user(self, pid: Optional[int]) -> Optional[str]:
        """Get the username associated with a process"""
        if not pid:
            return None
        
        try:
            process = psutil.Process(pid)
            return process.username()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    
    def get_system_info(self) -> Dict:
        """Get system information and resource usage"""
        try:
            # CPU information
            cpu_info = {
                'usage_percent': psutil.cpu_percent(interval=1),
                'count': psutil.cpu_count(),
                'count_logical': psutil.cpu_count(logical=True),
                'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
            }
            
            # Memory information
            memory = psutil.virtual_memory()
            memory_info = {
                'total': memory.total,
                'available': memory.available,
                'used': memory.used,
                'percent': memory.percent
            }
            
            # Disk information
            disk = psutil.disk_usage('C:\\')
            disk_info = {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': (disk.used / disk.total) * 100
            }
            
            # Network statistics
            net_io = psutil.net_io_counters()
            network_info = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
            
            return {
                'timestamp': datetime.now().isoformat(),
                'cpu': cpu_info,
                'memory': memory_info,
                'disk': disk_info,
                'network': network_info,
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
        
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {}
    
    def get_windows_services(self) -> List[Dict]:
        """Get Windows services related to remote access"""
        services = []
        
        if not win32service:
            logger.warning("win32service not available, skipping Windows services check")
            return services
        
        try:
            # Services to monitor
            service_names = [
                'TermService',  # Remote Desktop Services
                'WinRM',        # Windows Remote Management
                'sshd',         # SSH Server
                'TeamViewer',   # TeamViewer
                'VNC',          # VNC Server
            ]
            
            for service_name in service_names:
                try:
                    service_handle = win32service.OpenService(
                        win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE),
                        service_name,
                        win32service.SERVICE_QUERY_STATUS
                    )
                    
                    status = win32service.QueryServiceStatus(service_handle)
                    
                    services.append({
                        'name': service_name,
                        'status': 'running' if status[1] == win32service.SERVICE_RUNNING else 'stopped',
                        'start_type': status[0],
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    win32service.CloseServiceHandle(service_handle)
                
                except Exception as e:
                    # Service might not exist
                    services.append({
                        'name': service_name,
                        'status': 'not_found',
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
        
        except Exception as e:
            logger.error(f"Error getting Windows services: {e}")
        
        return services
    
    def terminate_connection(self, pid: int, force: bool = False) -> bool:
        """Terminate a connection by killing the associated process"""
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            
            logger.info(f"Attempting to terminate process {pid} ({process_name})")
            
            if force:
                process.kill()
            else:
                process.terminate()
            
            # Wait for process to terminate
            process.wait(timeout=10)
            
            logger.info(f"Successfully terminated process {pid}")
            return True
        
        except psutil.NoSuchProcess:
            logger.warning(f"Process {pid} not found")
            return False
        except psutil.AccessDenied:
            logger.error(f"Access denied when trying to terminate process {pid}")
            return False
        except Exception as e:
            logger.error(f"Error terminating process {pid}: {e}")
            return False
    
    def block_ip_address(self, ip_address: str, port: Optional[int] = None) -> bool:
        """Block an IP address using Windows Firewall"""
        try:
            # Create Windows Firewall rule using netsh
            rule_name = f"RemoteMonitor_Block_{ip_address}_{int(time.time())}"
            
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=in',
                'action=block',
                f'remoteip={ip_address}'
            ]
            
            if port:
                cmd.extend([f'localport={port}'])
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            logger.info(f"Successfully blocked IP {ip_address} (rule: {rule_name})")
            return True
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP {ip_address}: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local and should not be looked up"""
        try:
            parts = [int(x) for x in ip.split('.')]
            if len(parts) != 4 or any(part < 0 or part > 255 for part in parts):
                return True  # Invalid IP, treat as private
            
            # Private IP ranges:
            # 10.0.0.0 - 10.255.255.255
            # 172.16.0.0 - 172.31.255.255
            # 192.168.0.0 - 192.168.255.255
            # 127.0.0.0 - 127.255.255.255 (loopback)
            return (
                parts[0] == 10 or
                parts[0] == 127 or
                (parts[0] == 172 and 16 <= parts[1] <= 31) or
                (parts[0] == 192 and parts[1] == 168)
            )
        except (ValueError, IndexError):
            return True  # Invalid IP format, treat as private
    
    def _clean_geoip_cache(self):
        """Clean expired GeoIP cache entries"""
        current_time = time.time()
        expired_keys = []
        
        for ip, data in self.geoip_cache.items():
            if current_time - data.get('timestamp', 0) > self.geoip_cache_ttl:
                expired_keys.append(ip)
        
        for key in expired_keys:
            del self.geoip_cache[key]
    
    def lookup_geoip(self, ip: str) -> Optional[Dict]:
        """Lookup GeoIP information for an IP address"""
        try:
            logger.debug(f"Starting GeoIP lookup for {ip}")
            
            # Clean cache periodically
            self._clean_geoip_cache()
            
            # Check if IP is private/local
            if self._is_private_ip(ip):
                logger.debug(f"IP {ip} is private/local, returning local data")
                return {
                    'country': 'Local',
                    'countryCode': 'LOCAL',
                    'city': 'Local Network',
                    'region': 'N/A',
                    'regionName': 'Local Network',
                    'isp': 'Local Network',
                    'org': 'Private Network',
                    'asn': 'N/A',
                    'query': ip,
                    'status': 'private'
                }
            
            # Check cache first
            if ip in self.geoip_cache:
                cached_data = self.geoip_cache[ip]
                if time.time() - cached_data.get('timestamp', 0) < self.geoip_cache_ttl:
                    logger.debug(f"Returning cached GeoIP data for {ip}")
                    return cached_data.get('data')
            
            # Rate limiting
            current_time = time.time()
            time_since_last = current_time - self.last_geoip_request
            if time_since_last < self.geoip_rate_limit:
                time.sleep(self.geoip_rate_limit - time_since_last)
            
            self.last_geoip_request = time.time()
            
            # Make API request
            url = f"{self.geoip_api_url}/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query"
            logger.info(f"Making GeoIP API request for {ip}: {url}")
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            logger.debug(f"GeoIP API response for {ip}: {data}")
            
            # Check if API returned success
            if data.get('status') != 'success':
                logger.warning(f"GeoIP lookup failed for {ip}: {data.get('message', 'Unknown error')}")
                return None
            
            # Transform API response to our format
            geo_data = {
                'country': data.get('country', 'Unknown'),
                'countryCode': data.get('countryCode', 'XX'),
                'city': data.get('city', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'regionName': data.get('regionName', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'org': data.get('org', 'Unknown'),
                'asn': data.get('as', 'Unknown'),
                'timezone': data.get('timezone', 'Unknown'),
                'lat': data.get('lat', 0),
                'lon': data.get('lon', 0),
                'query': data.get('query', ip),
                'status': 'success'
            }
            
            # Cache the result
            self.geoip_cache[ip] = {
                'data': geo_data,
                'timestamp': time.time()
            }
            
            logger.info(f"Successfully looked up GeoIP for {ip}: {geo_data.get('country', 'Unknown')}, {geo_data.get('city', 'Unknown')}")
            return geo_data
            
        except Exception as e:
            logger.error(f"Error looking up GeoIP for {ip}: {e}")
            return None
    
    def _is_suspicious_country(self, country_code: str) -> str:
        """Check if a country is considered suspicious and return risk level"""
        if not country_code:
            return 'none'
            
        country_upper = country_code.upper()
        
        # CRITICAL risk countries (known for state-sponsored attacks)
        critical_countries = [
            'KP',  # North Korea
            'IR',  # Iran
            'SY',  # Syria
        ]
        
        # HIGH risk countries (frequent source of attacks)
        high_risk_countries = [
            'CN',  # China
            'RU',  # Russia
            'CU',  # Cuba
            'SD',  # Sudan
            'AF',  # Afghanistan
            'IQ',  # Iraq
            'LY',  # Libya
            'SO',  # Somalia
            'YE',  # Yemen
            'MM',  # Myanmar
            'BY',  # Belarus
            'VE',  # Venezuela
        ]
        
        if country_upper in critical_countries:
            return 'critical'
        elif country_upper in high_risk_countries:
            return 'high'
        else:
            return 'none'
    
    def send_to_api(self, endpoint: str, data: Dict) -> bool:
        """Send data to the Node.js API"""
        try:
            url = f"{self.api_base_url}/python/{endpoint}"
            
            # Add authentication header for Python service
            headers = {
                'Content-Type': 'application/json',
                'X-API-Key': 'python-monitor-key-change-in-production'  # Should match backend
            }
            
            # Enhanced logging for security alerts
            if endpoint == 'security/alert':
                logger.info(f"Sending security alert to API: {data.get('alert_type')} - {data.get('severity')} - {data.get('message', '')[:100]}...")
            
            response = requests.post(url, json=data, headers=headers, timeout=10)
            response.raise_for_status()
            
            if endpoint == 'security/alert':
                logger.info(f"Security alert sent successfully: {data.get('alert_type')} ({data.get('severity')})")
            else:
                logger.info(f"Successfully sent data to {endpoint}")
            return True
        
        except requests.exceptions.RequestException as e:
            if endpoint == 'security/alert':
                logger.error(f"❌ Failed to send security alert to API {endpoint}: {e}")
                logger.error(f"Alert data: {data}")
            else:
                logger.error(f"Failed to send data to API {endpoint}: {e}")
            return False
    
    async def monitor_loop(self):
        """Main monitoring loop"""
        logger.info("Starting connection monitoring loop")
        
        while True:
            try:
                # Get current connections
                connections = self.get_network_connections()
                
                # Check for new connections
                current_connection_ids = set()
                for conn in connections:
                    conn_id = f"{conn['remote_ip']}:{conn['remote_port']}-{conn['local_port']}"
                    current_connection_ids.add(conn_id)
                    
                    # If this is a new connection, send to API
                    if conn_id not in self.known_connections:
                        logger.info(f"New remote connection detected: {conn['remote_ip']}:{conn['remote_port']} -> {conn['local_port']} ({conn['connection_type']})")
                        
                        # Send to API
                        self.send_to_api('connections/new', conn)
                        
                        self.known_connections.add(conn_id)
                
                # Check for closed connections
                closed_connections = self.known_connections - current_connection_ids
                for conn_id in closed_connections:
                    logger.info(f"Connection closed: {conn_id}")
                    
                    # Parse connection ID to get connection details
                    try:
                        parts = conn_id.split('-')
                        if len(parts) >= 2:
                            remote_part = parts[0].split(':')
                            if len(remote_part) == 2:
                                remote_ip, remote_port = remote_part
                                local_port = parts[1]
                                
                                # Send connection closed event to API
                                closed_data = {
                                    'remote_ip': remote_ip,
                                    'remote_port': int(remote_port),
                                    'local_port': local_port,
                                    'timestamp': datetime.now().isoformat()
                                }
                                self.send_to_api('connections/closed', closed_data)
                    except Exception as e:
                        logger.error(f"Error parsing closed connection ID {conn_id}: {e}")
                    
                    self.known_connections.remove(conn_id)
                
                # Send system info periodically (every 10 iterations)
                if len(self.known_connections) % 10 == 0:
                    system_info = self.get_system_info()
                    self.send_to_api('monitoring/system-info', system_info)
                
                # Send security alerts for suspicious activity
                await self.check_and_send_security_alerts(connections)
                
                # Wait before next check
                await asyncio.sleep(self.poll_interval)
            
            except KeyboardInterrupt:
                logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(self.poll_interval)
    
    async def check_and_send_security_alerts(self, connections: List[Dict]) -> None:
        """Check for suspicious activity and send security alerts"""
        try:
            current_time = time.time()
            
            # Track connection attempts per IP with timestamps
            ip_attempts = {}
            for conn in connections:
                ip = conn['remote_ip']
                if ip not in ip_attempts:
                    ip_attempts[ip] = []
                ip_attempts[ip].append(current_time)
            
            # Check for multiple connection attempts in the last 5 minutes
            five_minutes_ago = current_time - 300  # 5 minutes in seconds
            
            for ip, timestamps in ip_attempts.items():
                # Filter timestamps to last 5 minutes
                recent_attempts = [t for t in timestamps if t >= five_minutes_ago]
                
                if len(recent_attempts) >= 6:  # 6+ attempts - CRITICAL severity
                    alert_data = {
                        'alert_type': 'MULTIPLE_ATTEMPTS',
                        'severity': 'CRITICAL',
                        'message': f'CRITICAL: Multiple connection attempts ({len(recent_attempts)}) from {ip} in the last 5 minutes - Possible brute force attack'
                    }
                    logger.critical(f"CRITICAL SECURITY ALERT: {alert_data['message']}")
                    self.send_to_api('security/alert', alert_data)
                elif len(recent_attempts) >= 4:  # 4-5 attempts - HIGH severity
                    alert_data = {
                        'alert_type': 'MULTIPLE_ATTEMPTS',
                        'severity': 'HIGH',
                        'message': f'Multiple connection attempts ({len(recent_attempts)}) from {ip} in the last 5 minutes'
                    }
                    logger.warning(f"HIGH SECURITY ALERT: {alert_data['message']}")
                    self.send_to_api('security/alert', alert_data)
                elif len(recent_attempts) >= 2:  # 2-3 attempts - MEDIUM severity
                    alert_data = {
                        'alert_type': 'MULTIPLE_ATTEMPTS',
                        'severity': 'MEDIUM',
                        'message': f'Multiple connection attempts ({len(recent_attempts)}) from {ip} detected'
                    }
                    logger.info(f"Security notice: {alert_data['message']}")
                    self.send_to_api('security/alert', alert_data)
            
            # Check for connections on suspicious ports
            suspicious_ports = [1234, 4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321]
            for conn in connections:
                if conn['remote_port'] in suspicious_ports:
                    alert_data = {
                        'alert_type': 'SUSPICIOUS_PORT',
                        'severity': 'MEDIUM',
                        'message': f'Connection from suspicious port {conn["remote_port"]} detected from {conn["remote_ip"]}'
                    }
                    logger.warning(f"Suspicious port alert: {alert_data['message']}")
                    self.send_to_api('security/alert', alert_data)
            
            # Check for non-standard protocols on standard ports
            for conn in connections:
                if conn['local_port'] == '3389' and conn['connection_type'] != 'RDP':
                    alert_data = {
                        'alert_type': 'UNUSUAL_ACTIVITY',
                        'severity': 'MEDIUM',
                        'message': f'Non-RDP connection on RDP port 3389 from {conn["remote_ip"]} (Type: {conn["connection_type"]})'
                    }
                    logger.warning(f"Unusual activity: {alert_data['message']}")
                    self.send_to_api('security/alert', alert_data)
                
                # Check for SSH on non-standard ports
                if conn['connection_type'] == 'SSH' and conn['local_port'] != '22':
                    alert_data = {
                        'alert_type': 'UNUSUAL_ACTIVITY',
                        'severity': 'LOW',
                        'message': f'SSH connection on non-standard port {conn["local_port"]} from {conn["remote_ip"]}'
                    }
                    logger.info(f"SSH on unusual port: {alert_data['message']}")
                    self.send_to_api('security/alert', alert_data)
            
            # Check for connections from suspicious countries
            for conn in connections:
                geo_data = conn.get('geoLocation')
                if geo_data and geo_data.get('countryCode'):
                    country_code = geo_data.get('countryCode')
                    risk_level = self._is_suspicious_country(country_code)
                    
                    if risk_level == 'critical':
                        alert_data = {
                            'alert_type': 'SUSPICIOUS_COUNTRY',
                            'severity': 'CRITICAL',
                            'message': f'CRITICAL: Connection from high-threat country {geo_data.get("country", "Unknown")} ({country_code}) detected from {conn["remote_ip"]} - State-sponsored threat risk'
                        }
                        logger.critical(f"CRITICAL COUNTRY THREAT: {alert_data['message']}")
                        self.send_to_api('security/alert', alert_data)
                    elif risk_level == 'high':
                        alert_data = {
                            'alert_type': 'SUSPICIOUS_COUNTRY',
                            'severity': 'HIGH',
                            'message': f'Connection from high-risk country {geo_data.get("country", "Unknown")} ({country_code}) detected from {conn["remote_ip"]}'
                        }
                        logger.warning(f"HIGH RISK COUNTRY: {alert_data['message']}")
                        self.send_to_api('security/alert', alert_data)
            
            # Check for failed connection patterns (if we can detect them)
            # This would require tracking connection states over time
            
            # Log summary of security check
            total_connections = len(connections)
            unique_ips = len(set(conn['remote_ip'] for conn in connections))
            logger.debug(f"Security check completed: {total_connections} connections from {unique_ips} unique IPs")
        
        except Exception as e:
             logger.error(f"Error checking security alerts: {e}")

    async def perform_scan(self) -> Dict:
        """Perform a one-time scan for remote connections"""
        scan_start_time = time.time()
        
        try:
            logger.info("Starting connection scan...")
            
            # Get current connections
            connections = self.get_network_connections()
            
            # Get system information
            system_info = self.get_system_info()
            
            # Get Windows services
            services = self.get_windows_services()
            
            scan_duration = time.time() - scan_start_time
            
            result = {
                'scan_duration': round(scan_duration * 1000),  # Convert to milliseconds
                'timestamp': datetime.now().isoformat(),
                'connections': connections,
                'system_info': system_info,
                'services': services,
                'summary': {
                    'total_connections': len(connections),
                    'connection_types': list(set(conn['connection_type'] for conn in connections)),
                    'unique_ips': list(set(conn['remote_ip'] for conn in connections))
                }
            }
            
            logger.info(f"Scan completed in {scan_duration:.2f} seconds. Found {len(connections)} connections.")
            return result
            
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return {
                'scan_duration': round((time.time() - scan_start_time) * 1000),
                'timestamp': datetime.now().isoformat(),
                'connections': [],
                'error': str(e)
            }

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Windows Remote Connection Monitor')
    parser.add_argument('--api-url', default='http://localhost:3001/api', help='API base URL')
    parser.add_argument('--interval', type=int, default=5, help='Polling interval in seconds')
    parser.add_argument('--log-level', default='INFO', help='Logging level')
    parser.add_argument('--scan', action='store_true', help='Perform a one-time scan and exit')
    
    args = parser.parse_args()
    
    # Set logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    
    # Create monitor instance
    monitor = WindowsConnectionMonitor(args.api_url, args.interval)
    
    # Handle scan mode
    if args.scan:
        try:
            result = asyncio.run(monitor.perform_scan())
            # Output JSON result for the Node.js backend to parse
            print(json.dumps(result, indent=2))
            return 0
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            error_result = {
                'scan_duration': 0,
                'timestamp': datetime.now().isoformat(),
                'connections': [],
                'error': str(e)
            }
            print(json.dumps(error_result, indent=2))
            return 1
    
    # Start continuous monitoring
    try:
        asyncio.run(monitor.monitor_loop())
    except KeyboardInterrupt:
        logger.info("Shutting down monitor")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main())