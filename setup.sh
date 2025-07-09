#!/bin/bash

# === mitmproxy Setup & Management Script ===

set -e

PROJECT_DIR=$(pwd)/../Evil_Proxy
DATA_DIR="$PROJECT_DIR/Data"
SCRIPT_NAME="script.py"
COMPOSE_NAME="docker-compose.yml"
USER_SCRIPTS_DIR="$PROJECT_DIR/UserScripts"

function check_dependencies() {
    echo "[+] Checking dependencies..."
    local CURRENT_DIR=$(pwd)
    cd $PROJECT_DIR
    command -v docker-compose >/dev/null 2>&1 || {
        echo "[!] docker-compose not found. Please install it."
        exit 1
    }
    cd $CURRENT_DIR
    echo "[✔] docker-compose is available"
}

function create_directories() {
    echo "[+] Creating directory structure..."
    mkdir $PROJECT_DIR
    mkdir $DATA_DIR
    local CURRENT_DIR=$(pwd)
    cd $PROJECT_DIR
    mkdir -p scripts certs "$USER_SCRIPTS_DIR"
    chmod 755 scripts "$USER_SCRIPTS_DIR"
    chmod 700 certs
    cd $CURRENT_DIR
    cd $DATA_DIR
    mkdir -p HAR_Out Tokens Other
    chmod 755 HAR_Out Tokens Other
    cd $CURRENT_DIR
}

function copy_capture_script() {
    if [[ -f "$SCRIPT_NAME" ]]; then
        cp "$SCRIPT_NAME" $PROJECT_DIR/scripts/
        echo "[✔] $SCRIPT_NAME copied to $PROJECT_DIR/scripts/"
    else
        echo "[!] $SCRIPT_NAME not found. Please add it to the '$PROJECT_DIR/scripts/' directory manually."
    fi
}

function copy_compose_file() {
    if [[ -f "$COMPOSE_NAME" ]]; then
        cp "$COMPOSE_NAME" $PROJECT_DIR/
        echo "[✔] $COMPOSE_NAME copied to $PROJECT_DIR"
    else
        echo "[!] $COMPOSE_NAME not found. Please add it to the '$PROJECT_DIR/' directory manually."
    fi
}

function create_management_scripts() {
    echo "[+] Generating management scripts..."

    cat > "$USER_SCRIPTS_DIR/start.sh" << 'EOF'
#!/bin/bash
echo "Starting mitmproxy traffic capture..."
docker-compose up -d
EOF

    cat > "$USER_SCRIPTS_DIR/stop.sh" << 'EOF'
#!/bin/bash
echo "Stopping mitmproxy traffic capture..."
docker-compose down
EOF

    cat > "$USER_SCRIPTS_DIR/logs.sh" << 'EOF'
#!/bin/bash
docker-compose logs -f mitmproxy
EOF

    cat > "$USER_SCRIPTS_DIR/status.sh" << 'EOF'
#!/bin/bash
echo "=== Service Status ==="
docker-compose ps
echo ""
echo "=== Recent Logs ==="
docker-compose logs --tail=20 mitmproxy
EOF

    cat > "$USER_SCRIPTS_DIR/cleanup.sh" << 'EOF'
#!/bin/bash
echo "Cleaning up old capture files (>30 days)..."
find ./captures -name "*.har" -mtime +30 -delete
find ./captures -type d -empty -delete
du -sh ./captures
EOF

    cat > "$USER_SCRIPTS_DIR/view_traffic.sh" << 'EOF'
#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: $0 <client_ip>"
    echo "Available client IPs:"
    find ./captures -type d -name "*.*.*.*" -o -name "*:*" | xargs -I {} basename {} | sort -u
    exit 1
fi

CLIENT_IP="$1"
TODAY=$(date +%Y-%m-%d)
CAPTURE_DIR="./captures/$TODAY/$CLIENT_IP"

echo "Recent traffic for $CLIENT_IP on $TODAY:"
if [ -d "$CAPTURE_DIR" ]; then
    ls -lt "$CAPTURE_DIR"
else
    echo "No traffic found for $CLIENT_IP today"
fi
EOF

    chmod +x "$USER_SCRIPTS_DIR"/*.sh
    echo "[✔] Management scripts created in $USER_SCRIPTS_DIR"
}

function print_summary() {
    echo ""
    echo "=== mitmproxy Setup Complete ==="
    echo ""
    echo "Use the following scripts inside '$USER_SCRIPTS_DIR':"
    echo "  start.sh        - Start the mitmproxy service"
    echo "  stop.sh         - Stop the service"
    echo "  logs.sh         - View live logs"
    echo "  status.sh       - Show service status and recent logs"
    echo "  cleanup.sh      - Delete captures older than 30 days"
    echo "  view_traffic.sh <IP> - Show today's traffic for a client"
    echo ""
    echo "To start the service: ./UserScripts/start.sh"
    echo "To stop it:           ./UserScripts/stop.sh"
    echo ""
    echo "Proxy:"
    echo "  HTTP Proxy     : localhost:8080"
    echo "  Web Interface  : http://localhost:8081"
    echo ""
    echo "Captured traffic: ./Data/HAR_Out/YYYY-MM-DD/CLIENT_IP/"
    echo "Certificate URL : http://mitm.it"
    echo ""
}

# === Main Flow ===

echo "=== Starting mitmproxy environment setup ==="
create_directories
check_dependencies
copy_capture_script
copy_compose_file
create_management_scripts
print_summary
