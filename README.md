# mitmproxy Traffic Capture & IP Blocking System

A comprehensive Docker-based mitmproxy setup with advanced traffic capture, token extraction, and intelligent IP blocking capabilities.

## Features

- **Traffic Capture**: Automatically captures HTTP/HTTPS traffic in HAR format
- **Token Extraction**: Extracts JWT tokens, cookies, and authorization headers
- **IP Blocking System**: Intelligent blocking based on authentication failures and connection patterns
- **Rate Limiting**: Prevents abuse through connection attempt monitoring
- **Auto-Recovery**: Automatic IP unblocking after configurable timeouts
- **Web Interface**: Built-in mitmproxy web interface for real-time monitoring
- **Persistent Storage**: All data persists across container restarts

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Basic understanding of HTTP proxies
- Network configuration access (for client setup)

### Installation

1. **Run the setup script:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

2. **Start the service:**
   ```bash
   cd ../Evil_Proxy
   ./UserScripts/start.sh
   ```

3. **Access the web interface:**
   - Web Interface: http://localhost:8081
   - Username: admin
   - Password: 1234

### Proxy Configuration

Configure clients to use the proxy:
- **HTTP Proxy**: `localhost:8080`
- **Proxy Authentication**: 
  - Username: `proxy`
  - Password: `112233`

## Directory Structure

```
Evil_Proxy/
├── docker-compose.yml          # Docker Compose configuration
├── scripts/
│   └── script.py              # Main mitmproxy script
├── Data/
│   ├── HAR_Out/               # Traffic captures (HAR files)
│   │   └── YYYY-MM-DD/
│   │       └── CLIENT_IP.har
│   ├── Tokens/                # Extracted tokens and credentials
│   │   └── domain.com/
│   │       └── CLIENT_IP.json
│   └── Other/
│       ├── blocked_ips.json   # Blocked IP database
│       └── debug.log          # Debug logging
├── certs/                     # mitmproxy certificates
└── UserScripts/               # Management scripts
    ├── start.sh
    ├── stop.sh
    ├── logs.sh
    ├── status.sh
    ├── cleanup.sh
    └── view_traffic.sh
```

## Management Scripts

### Basic Operations

- **Start service**: `./UserScripts/start.sh`
- **Stop service**: `./UserScripts/stop.sh`
- **View logs**: `./UserScripts/logs.sh`
- **Check status**: `./UserScripts/status.sh`

### Maintenance

- **Cleanup old files**: `./UserScripts/cleanup.sh`
- **View client traffic**: `./UserScripts/view_traffic.sh <CLIENT_IP>`

## IP Blocking System

### Automatic Blocking

The system automatically blocks IPs based on:

1. **Authentication Failures**: 
   - HTTP 407 (Proxy Authentication Required)
   - HTTP 401 (Unauthorized)
   - HTTP 403 (Forbidden)
   - Default threshold: 10 failures

2. **Connection Rate Limiting**:
   - Rapid connection attempts within 30 seconds
   - Default threshold: 10 connections

### Configuration

Key blocking parameters in `script.py`:

```python
BLOCK_RESET_INTERVAL = timedelta(hours=1)  # Auto-unblock after 1 hour
BLOCK_THRESHOLD = 10                       # Block after 10 attempts
CONNECTION_TIMEOUT = 30                    # Seconds to track connections
CLEANUP_INTERVAL = 60                      # Cleanup check interval
```

### Manual IP Management

Access the Python console within the container:

```bash
docker exec -it Evil_Proxy python3 -c "
import sys
sys.path.append('/home/mitmproxy/scripts')
from script import *

# Block an IP
print(block_ip('192.168.1.100'))

# Unblock an IP
print(unblock_ip('192.168.1.100'))

# List blocked IPs
print(list_blocked_ips())

# Get debug info
print(get_debug_info())
"
```

## Traffic Capture

### HAR Files

Traffic is automatically captured in HAR format:
- Location: `Data/HAR_Out/YYYY-MM-DD/CLIENT_IP.har`
- Format: Standard HAR 1.2 specification
- Updates: Real-time (saved every 60 seconds)

### Token Extraction

Automatically extracts and saves:
- **JWT Tokens**: From headers and request bodies
- **Cookies**: All HTTP cookies with metadata
- **Authorization Headers**: Bearer tokens, Basic auth, etc.

Extracted data location: `Data/Tokens/DOMAIN/CLIENT_IP.json`

Example extracted data:
```json
{
  "cookies": [
    {
      "domain": ".example.com",
      "name": "session_id",
      "value": "abc123",
      "path": "/",
      "httpOnly": false,
      "secure": false
    }
  ],
  "authorization": "Bearer eyJhbGciOiJIUzI1NiIs...",
  "jwts": [
    "eyJhbGciOiJIUzI1NiIs..."
  ]
}
```

## Configuration

### Docker Compose Settings

Key configuration options in `docker-compose.yml`:

```yaml
environment:
  - PYTHONUNBUFFERED=1
command: >
  mitmweb 
  --mode regular 
  --showhost 
  --web-password=1234
  --proxyauth="proxy:112233"
  --web-host 0.0.0.0
  --web-port 8081
```

### Script Configuration

Modify settings in `script.py`:

- **Data directories**: `DATA_DIR`, `CAPTURE_DIR`, `EXTRACT_DIR`
- **Blocking thresholds**: `BLOCK_THRESHOLD`, `BLOCK_RESET_INTERVAL`
- **Logging**: `DEBUG_LOG` path and verbosity
- **Save intervals**: `save_interval` for HAR files

## Security Considerations

### Authentication

- **Proxy Authentication**: Required for all connections
- **Web Interface**: Password-protected admin panel
- **Network Isolation**: Uses Docker bridge networking

### Data Protection

- **Certificate Storage**: Secure cert directory with restricted permissions
- **Log Rotation**: Automatic cleanup of old capture files
- **Access Control**: Container-based isolation

### Monitoring

- **Debug Logging**: Comprehensive logging to `Data/Other/debug.log`
- **Real-time Monitoring**: Web interface shows live traffic
- **Status Reporting**: Periodic status updates in logs

## Troubleshooting

### Common Issues

1. **Permission Denied**:
   ```bash
   sudo chown -R 1000:1000 Data/
   chmod 755 Data/HAR_Out Data/Tokens Data/Other
   ```

2. **Port Conflicts**:
   - Change ports in `docker-compose.yml`
   - Update proxy settings accordingly

3. **Certificate Issues**:
   - Visit http://mitm.it to download certificates
   - Install CA certificate on client devices

4. **High Memory Usage**:
   - Adjust `save_interval` in script.py
   - Run cleanup script more frequently

### Debug Mode

Enable detailed logging:

```bash
docker-compose logs -f mitmproxy | grep -E "(DEBUG|BLOCKED|ERROR)"
```

View debug log:
```bash
tail -f Data/Other/debug.log
```

### Performance Tuning

For high-traffic environments:

1. **Reduce save interval**:
   ```python
   self.save_interval = 30  # Save every 30 seconds
   ```

2. **Increase cleanup frequency**:
   ```python
   CLEANUP_INTERVAL = 30  # Check every 30 seconds
   ```

3. **Add resource limits**:
   ```yaml
   deploy:
     resources:
       limits:
         memory: 1G
         cpus: '1.0'
   ```

## API Integration

### Programmatic Access

The blocking system can be controlled programmatically:

```python
# Example: Custom blocking logic
def custom_block_check(flow):
    client_ip = get_client_ip(flow)
    
    # Custom rules
    if suspicious_pattern(flow.request):
        capture.block_ip(client_ip, "Suspicious pattern detected")
    
    # Integration with external threat feeds
    if is_malicious_ip(client_ip):
        capture.block_ip(client_ip, "Threat intelligence match")
```

## License

This project is intended for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

## Support

For issues and questions:
1. Check the debug log: `Data/Other/debug.log`
2. Review container logs: `docker-compose logs mitmproxy`
3. Verify network configuration and proxy settings
4. Ensure proper certificate installation on client devices
