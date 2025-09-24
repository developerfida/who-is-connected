# Windows Remote Connection Monitor - Python Service

This Python service monitors remote connections on Windows 11 systems and integrates with the Node.js backend.

## Features

- **Real-time Connection Monitoring**: Detects all remote connections (RDP, SSH, VNC, TeamViewer, etc.)
- **System Resource Monitoring**: Tracks CPU, memory, disk, and network usage
- **Windows Service Integration**: Monitors Windows services related to remote access
- **Connection Termination**: Can terminate suspicious connections
- **IP Blocking**: Integrates with Windows Firewall to block malicious IPs
- **API Integration**: Sends data to Node.js backend via REST API

## Requirements

- Python 3.8 or higher
- Windows 10/11
- Administrator privileges (for some features)
- Node.js backend running on localhost:3001

## Installation

### Option 1: Using the Batch Script (Recommended)

1. Open Command Prompt as Administrator
2. Navigate to the python directory
3. Run the installation script:
   ```cmd
   install_and_run.bat
   ```

### Option 2: Manual Installation

1. Install Python dependencies:
   ```cmd
   pip install -r requirements.txt
   ```

2. Run the monitor:
   ```cmd
   python connection_monitor.py
   ```

## Usage

### Basic Usage

```cmd
python connection_monitor.py
```

### Advanced Usage

```cmd
python connection_monitor.py --api-url http://localhost:3001/api --interval 5 --log-level INFO
```

### Command Line Options

- `--api-url`: Base URL for the Node.js API (default: http://localhost:3001/api)
- `--interval`: Polling interval in seconds (default: 5)
- `--log-level`: Logging level (DEBUG, INFO, WARNING, ERROR)

## Detected Connection Types

The monitor can detect and classify the following types of remote connections:

- **RDP (Remote Desktop Protocol)**: Port 3389
- **SSH (Secure Shell)**: Port 22
- **VNC (Virtual Network Computing)**: Ports 5900, 5901
- **TeamViewer**: Port 5938
- **WinRM (Windows Remote Management)**: Ports 5985, 5986
- **Other**: Any other remote connections

## Security Features

### Connection Termination

The service can terminate suspicious connections by killing the associated process:

```python
monitor.terminate_connection(pid=1234, force=True)
```

### IP Blocking

Integrates with Windows Firewall to block malicious IP addresses:

```python
monitor.block_ip_address('192.168.1.100', port=3389)
```

## Monitoring Data

### Connection Information

For each detected connection, the following information is collected:

- Local and remote IP addresses and ports
- Protocol (TCP/UDP)
- Connection type (RDP, SSH, VNC, etc.)
- Process ID and name
- Username associated with the connection
- Timestamp

### System Information

- CPU usage and core count
- Memory usage (total, used, available)
- Disk usage
- Network I/O statistics
- System uptime

### Windows Services

Monitors the status of remote access services:

- Remote Desktop Services (TermService)
- Windows Remote Management (WinRM)
- SSH Server (sshd)
- TeamViewer Service
- VNC Server

## Integration with Node.js Backend

The Python service communicates with the Node.js backend through REST API calls:

- `POST /api/connections/new`: Reports new connections
- `POST /api/monitoring/system-info`: Sends system information
- `POST /api/security/alerts`: Reports security alerts

## Logging

The service logs all activities to:

- Console output
- `connection_monitor.log` file

Log levels:
- **DEBUG**: Detailed debugging information
- **INFO**: General information about connections and system status
- **WARNING**: Warning messages about potential issues
- **ERROR**: Error messages about failures

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   - Run Command Prompt as Administrator
   - Some Windows APIs require elevated privileges

2. **Module Import Errors**
   - Ensure all dependencies are installed: `pip install -r requirements.txt`
   - Check Python version compatibility

3. **API Connection Errors**
   - Verify Node.js backend is running on localhost:3001
   - Check firewall settings
   - Verify API URL configuration

4. **WMI Connection Errors**
   - WMI might be disabled or corrupted
   - Try running `winmgmt /verifyrepository` as Administrator

### Performance Considerations

- Default polling interval is 5 seconds
- Increase interval for lower system impact
- Monitor system resources when running

## Security Considerations

- Run with minimum required privileges
- Monitor log files for sensitive information
- Secure API communication in production
- Regular updates of dependencies

## Development

### Adding New Connection Types

1. Update `_identify_connection_type()` method
2. Add port mappings and process name patterns
3. Test with actual connections

### Extending System Monitoring

1. Add new metrics to `get_system_info()` method
2. Update API endpoints to handle new data
3. Consider performance impact

## License

This software is part of the Remote Connection Monitor application.