# Remote Connection Monitor

A comprehensive security application that monitors, detects, and manages all remote connections to Windows 11 computers in real-time.

## 🚀 Features

- **Real-time Connection Monitoring**: Detects all remote connections (RDP, SSH, VNC, TeamViewer, etc.)
- **Security Dashboard**: Web-based interface with live updates
- **Connection History**: Detailed logs with search and filtering
- **Security Alerts**: Automated threat detection and notifications
- **Connection Control**: Terminate suspicious connections and block IPs
- **System Monitoring**: Resource usage and service status tracking
- **Multi-layer Architecture**: React frontend, Node.js backend, Python monitoring service

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React Web    │    │   Node.js API   │    │ Python Monitor  │
│   Dashboard     │◄──►│   + Socket.io   │◄──►│    Service      │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │   MongoDB       │    │ Windows System  │
                       │   Database      │    │     APIs        │
                       └─────────────────┘    └─────────────────┘
```

## 🛠️ Technology Stack

### Frontend
- **React 18** with TypeScript
- **Tailwind CSS** for styling
- **Vite** for build tooling
- **Zustand** for state management
- **Socket.io Client** for real-time updates
- **React Router** for navigation

### Backend
- **Node.js 18+** with Express
- **TypeScript** for type safety
- **Socket.io** for WebSocket communication
- **MongoDB** with Mongoose ODM
- **JWT** authentication
- **bcrypt** for password hashing
- **Helmet** for security headers

### Monitoring Service
- **Python 3.11+**
- **psutil** for system monitoring
- **pywin32** for Windows APIs
- **requests** for API communication
- **asyncio** for async operations

## 📋 Prerequisites

- **Node.js 18+** and npm
- **Python 3.8+** with pip
- **MongoDB** (local or MongoDB Atlas)
- **Windows 10/11** (for monitoring service)
- **Administrator privileges** (for some monitoring features)

## 🚀 Quick Start

### 1. Clone and Install Dependencies

```bash
# Clone the repository
git clone <repository-url>
cd antivirous-app

# Install Node.js dependencies
npm install

# Install Python dependencies
cd python
pip install -r requirements.txt
cd ..
```

### 2. Environment Setup

```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your configuration
# At minimum, set:
# - MONGODB_URI
# - JWT_SECRET
# - PYTHON_API_KEY
```

### 3. Database Setup

Ensure MongoDB is running:

```bash
# Local MongoDB
mongod

# Or use MongoDB Atlas (cloud)
# Update MONGODB_URI in .env file
```

### 4. Start the Application

```bash
# Start both frontend and backend
npm run dev

# This runs:
# - Frontend: http://localhost:5173
# - Backend API: http://localhost:3001
```

### 5. Start Python Monitoring Service

Open a new terminal as **Administrator**:

```bash
cd python
python connection_monitor.py

# Or use the batch script:
install_and_run.bat
```

### 6. Access the Application

Open your browser and navigate to: `http://localhost:5173`

**Default Admin Credentials:**
- Username: `admin`
- Password: `admin123`

## 📖 Usage Guide

### Dashboard
- View real-time active connections
- Monitor security alerts
- See connection statistics
- Quick actions for connection management

### Connection History
- Browse all past connections
- Filter by IP, date, type, status
- Export data to CSV
- View detailed connection information

### Security Settings
- Configure blocking rules
- Set up alert notifications
- Manage security policies
- Acknowledge security alerts

### System Monitor
- View system resource usage
- Monitor Windows services
- Track network statistics
- Check service status

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|----------|
| `MONGODB_URI` | MongoDB connection string | `mongodb://localhost:27017/remote-connection-monitor` |
| `JWT_SECRET` | Secret key for JWT tokens | `your-super-secret-jwt-key-change-in-production` |
| `JWT_EXPIRES_IN` | JWT token expiration | `24h` |
| `FRONTEND_URL` | Frontend URL for CORS | `http://localhost:5173` |
| `PYTHON_API_KEY` | API key for Python service | `python-monitor-key-change-in-production` |
| `PORT` | Backend server port | `3001` |

### Python Service Configuration

```bash
# Command line options
python connection_monitor.py --help

# Custom API URL
python connection_monitor.py --api-url http://localhost:3001/api

# Custom polling interval
python connection_monitor.py --interval 10

# Debug logging
python connection_monitor.py --log-level DEBUG
```

## 🔒 Security Features

### Connection Detection
- **RDP (Port 3389)**: Remote Desktop Protocol
- **SSH (Port 22)**: Secure Shell
- **VNC (Ports 5900-5901)**: Virtual Network Computing
- **TeamViewer (Port 5938)**: TeamViewer remote access
- **WinRM (Ports 5985-5986)**: Windows Remote Management
- **Custom Protocols**: Other remote access tools

### Security Alerts
- **Multiple Connection Attempts**: Repeated connections from same IP
- **Suspicious Ports**: Connections from unusual ports
- **Unauthorized Access**: Failed authentication attempts
- **Unusual Activity**: Non-standard protocols on standard ports

### Protection Mechanisms
- **Connection Termination**: Kill suspicious processes
- **IP Blocking**: Windows Firewall integration
- **Real-time Alerts**: Immediate notifications
- **Access Control**: Role-based permissions

## 🧪 Development

### Project Structure

```
antivirous-app/
├── src/                    # React frontend
│   ├── components/         # Reusable components
│   ├── pages/             # Page components
│   ├── hooks/             # Custom hooks
│   ├── stores/            # Zustand stores
│   └── lib/               # Utilities and API
├── api/                   # Node.js backend
│   ├── routes/            # API routes
│   ├── models/            # MongoDB models
│   ├── middleware/        # Express middleware
│   ├── config/            # Configuration
│   └── websocket/         # Socket.io handlers
├── python/                # Python monitoring service
│   ├── connection_monitor.py  # Main monitoring script
│   ├── requirements.txt   # Python dependencies
│   └── README.md          # Python service docs
└── .trae/documents/       # Project documentation
```

### Available Scripts

```bash
# Development
npm run dev              # Start both frontend and backend
npm run client:dev       # Start frontend only
npm run server:dev       # Start backend only

# Building
npm run build           # Build for production
npm run preview         # Preview production build

# Code Quality
npm run lint            # Run ESLint
npm run check           # TypeScript type checking
```

### API Endpoints

#### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `GET /api/auth/profile` - Get user profile
- `POST /api/auth/logout` - User logout

#### Connections
- `GET /api/connections/active` - Get active connections
- `GET /api/connections/history` - Get connection history
- `GET /api/connections/:id` - Get connection details
- `POST /api/connections/:id/terminate` - Terminate connection
- `POST /api/connections/:id/block` - Block connection

#### Settings
- `GET /api/settings/blocking-rules` - Get blocking rules
- `POST /api/settings/blocking-rules` - Create blocking rule
- `GET /api/settings/alerts` - Get security alerts
- `POST /api/settings/alerts/:id/acknowledge` - Acknowledge alert

#### Monitoring
- `GET /api/monitoring/status` - Get system status
- `GET /api/monitoring/services` - Get Windows services
- `GET /api/monitoring/network` - Get network statistics
- `GET /api/monitoring/resources` - Get resource usage

#### Python Integration
- `POST /api/python/connections/new` - New connection from Python
- `POST /api/python/connections/closed` - Connection closed
- `POST /api/python/monitoring/system-info` - System information
- `POST /api/python/security/alert` - Security alert

## 🐛 Troubleshooting

### Common Issues

1. **MongoDB Connection Error**
   ```bash
   # Check if MongoDB is running
   mongod --version
   
   # Start MongoDB service
   net start MongoDB
   ```

2. **Python Service Permission Errors**
   ```bash
   # Run as Administrator
   # Right-click Command Prompt → "Run as administrator"
   ```

3. **Port Already in Use**
   ```bash
   # Check what's using the port
   netstat -ano | findstr :3001
   
   # Kill the process
   taskkill /PID <process_id> /F
   ```

4. **WebSocket Connection Issues**
   - Check firewall settings
   - Verify CORS configuration
   - Ensure both frontend and backend are running

### Logs and Debugging

```bash
# Backend logs
npm run server:dev

# Python service logs
cd python
python connection_monitor.py --log-level DEBUG

# Check log files
tail -f python/connection_monitor.log
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📞 Support

For support and questions:
- Check the troubleshooting section
- Review the logs for error messages
- Ensure all prerequisites are installed
- Verify environment configuration

## 🔄 Updates

To update the application:

```bash
# Update Node.js dependencies
npm update

# Update Python dependencies
cd python
pip install -r requirements.txt --upgrade
```

---

**⚠️ Security Notice**: This application monitors system-level network connections and requires administrator privileges. Always review the code and run it in a secure environment. Change default passwords and API keys before production use.