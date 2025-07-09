#!/usr/bin/env python3

import os
import json
import time
import base64
import re
from datetime import datetime, timedelta
from pathlib import Path
import threading
from collections import defaultdict
from mitmproxy import http, ctx
from mitmproxy.script import concurrent

# === Config Paths ===
DATA_DIR = Path("/home/mitmproxy/Data")
CAPTURE_DIR = DATA_DIR / "HAR_Out"
EXTRACT_DIR = DATA_DIR / "Tokens"
BLOCKLIST_FILE = DATA_DIR / "Other" / "blocked_ips.json"
DEBUG_LOG = DATA_DIR / "Other" / "debug.log"

DATA_DIR.mkdir(parents=True, exist_ok=True)
CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
BLOCKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)

JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+')

# Configuration
BLOCK_RESET_INTERVAL = timedelta(hours=1)  # Auto-unblock after 1 hour
BLOCK_THRESHOLD = 10  # Block after 10 attempts
CLEANUP_INTERVAL = 60  # Check every 1 minute for more responsive unblocking
CONNECTION_TIMEOUT = 30  # Seconds to track connection attempts

def debug_log(message):
    """Enhanced debug logging"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    try:
        with open(DEBUG_LOG, "a") as f:
            f.write(log_message + "\n")
    except:
        pass
    ctx.log.info(f"[DEBUG] {message}")

# === HAR Capturer ===
class TrafficCapture:
    def __init__(self):
        self.base_dir = CAPTURE_DIR
        self.flows = defaultdict(list)
        self.save_interval = 60
        self.lock = threading.Lock()
        self.blocked_ips = {}  # IP -> block_time mapping
        self.to_block = defaultdict(int)  # IP -> failure count
        self.connection_attempts = defaultdict(list)  # IP -> [timestamps]
        self.block_threshold = BLOCK_THRESHOLD
        self._load_blocked_ips()
        
        # Start background threads
        self._start_background_threads()
        
        debug_log(f"TrafficCapture initialized with threshold: {self.block_threshold}")

    def _start_background_threads(self):
        """Start all background threads"""
        threading.Thread(target=self._periodic_save, daemon=True).start()
        threading.Thread(target=self._periodic_cleanup, daemon=True).start()
        threading.Thread(target=self._periodic_status, daemon=True).start()

    def _periodic_status(self):
        """Periodically log status for debugging"""
        while True:
            time.sleep(300)  # Every 5 minutes
            with self.lock:
                blocked_count = len(self.blocked_ips)
                pending_count = len(self.to_block)
                connection_count = len(self.connection_attempts)
                debug_log(f"Status: {blocked_count} blocked, {pending_count} pending, {connection_count} tracked connections")
                
                if self.blocked_ips:
                    current_time = datetime.now()
                    for ip, block_time_str in self.blocked_ips.items():
                        try:
                            block_time = datetime.fromisoformat(block_time_str)
                            time_remaining = BLOCK_RESET_INTERVAL - (current_time - block_time)
                            if time_remaining.total_seconds() > 0:
                                debug_log(f"  Blocked: {ip} - {time_remaining.total_seconds():.0f}s remaining")
                        except:
                            debug_log(f"  Blocked: {ip} - invalid timestamp")

    def _load_blocked_ips(self):
        """Load blocked IPs from file"""
        if BLOCKLIST_FILE.exists():
            try:
                with open(BLOCKLIST_FILE) as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self.blocked_ips = data
                    else:
                        # Old format - convert to new format
                        self.blocked_ips = {}
                        for ip in data:
                            self.blocked_ips[ip] = datetime.now().isoformat()
                debug_log(f"Loaded {len(self.blocked_ips)} blocked IPs from file")
            except Exception as e:
                debug_log(f"Failed to load blocked IPs: {e}")
                self.blocked_ips = {}

    def _save_blocked_ips(self):
        """Save blocked IPs to file"""
        try:
            with open(BLOCKLIST_FILE, "w") as f:
                json.dump(self.blocked_ips, f, indent=2)
            debug_log(f"Saved {len(self.blocked_ips)} blocked IPs to file")
        except Exception as e:
            debug_log(f"Failed to save blocked IPs: {e}")

    def _periodic_cleanup(self):
        """Periodically unblock IPs and clean up old connection attempts"""
        debug_log("Starting periodic cleanup thread")
        while True:
            time.sleep(CLEANUP_INTERVAL)
            try:
                self._cleanup_expired_blocks()
                self._cleanup_old_connections()
            except Exception as e:
                debug_log(f"Error in periodic cleanup: {e}")

    def _cleanup_expired_blocks(self):
        """Remove expired IP blocks"""
        current_time = datetime.now()
        to_unblock = []
        
        with self.lock:
            for ip, block_time_str in self.blocked_ips.items():
                try:
                    block_time = datetime.fromisoformat(block_time_str)
                    if current_time - block_time > BLOCK_RESET_INTERVAL:
                        to_unblock.append(ip)
                except (ValueError, TypeError):
                    debug_log(f"Invalid timestamp for {ip}: {block_time_str}")
                    to_unblock.append(ip)
            
            if to_unblock:
                for ip in to_unblock:
                    del self.blocked_ips[ip]
                    if ip in self.to_block:
                        del self.to_block[ip]
                    if ip in self.connection_attempts:
                        del self.connection_attempts[ip]
                    debug_log(f"AUTO-UNBLOCKED {ip} after {BLOCK_RESET_INTERVAL}")
                
                self._save_blocked_ips()
                ctx.log.info(f"Auto-unblocked {len(to_unblock)} IPs after timeout")

    def _cleanup_old_connections(self):
        """Clean up old connection attempt records"""
        current_time = time.time()
        cutoff_time = current_time - CONNECTION_TIMEOUT
        
        with self.lock:
            for ip in list(self.connection_attempts.keys()):
                # Remove old attempts
                self.connection_attempts[ip] = [
                    t for t in self.connection_attempts[ip] 
                    if t > cutoff_time
                ]
                # Remove IPs with no recent attempts
                if not self.connection_attempts[ip]:
                    del self.connection_attempts[ip]

    def track_connection_attempt(self, ip):
        """Track connection attempts and block if too many"""
        current_time = time.time()
        
        with self.lock:
            if ip in self.blocked_ips:
                debug_log(f"Connection attempt from already blocked IP: {ip}")
                return True  # Already blocked
            
            # Add current attempt
            self.connection_attempts[ip].append(current_time)
            
            # Remove old attempts
            cutoff_time = current_time - CONNECTION_TIMEOUT
            self.connection_attempts[ip] = [
                t for t in self.connection_attempts[ip] 
                if t > cutoff_time
            ]
            
            attempt_count = len(self.connection_attempts[ip])
            debug_log(f"Connection attempt from {ip}: {attempt_count} attempts in {CONNECTION_TIMEOUT}s")
            
            # Block if too many attempts
            if attempt_count >= self.block_threshold:
                self.blocked_ips[ip] = datetime.now().isoformat()
                if ip in self.to_block:
                    del self.to_block[ip]
                del self.connection_attempts[ip]
                self._save_blocked_ips()
                debug_log(f"BLOCKED {ip} after {attempt_count} connection attempts")
                ctx.log.warn(f"[BLOCKED] {ip} blocked after {attempt_count} rapid connection attempts")
                return True
            
            return False

    def is_ip_blocked(self, ip):
        """Check if an IP is currently blocked"""
        with self.lock:
            if ip in self.blocked_ips:
                # Double-check if block has expired
                try:
                    block_time = datetime.fromisoformat(self.blocked_ips[ip])
                    if datetime.now() - block_time > BLOCK_RESET_INTERVAL:
                        # Block has expired, remove it
                        del self.blocked_ips[ip]
                        if ip in self.to_block:
                            del self.to_block[ip]
                        if ip in self.connection_attempts:
                            del self.connection_attempts[ip]
                        self._save_blocked_ips()
                        debug_log(f"AUTO-UNBLOCKED {ip} during check (expired)")
                        return False
                    return True
                except:
                    # Invalid timestamp, unblock
                    del self.blocked_ips[ip]
                    return False
            return False

    def block_ip(self, ip, reason="Manual"):
        """Block an IP address"""
        with self.lock:
            self.blocked_ips[ip] = datetime.now().isoformat()
            if ip in self.to_block:
                del self.to_block[ip]
            if ip in self.connection_attempts:
                del self.connection_attempts[ip]
            self._save_blocked_ips()
            debug_log(f"BLOCKED {ip} - Reason: {reason}")
            ctx.log.warn(f"[BLOCKED] {ip} - {reason}")

    def unblock_ip(self, ip):
        """Unblock an IP address"""
        with self.lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                if ip in self.to_block:
                    del self.to_block[ip]
                if ip in self.connection_attempts:
                    del self.connection_attempts[ip]
                self._save_blocked_ips()
                debug_log(f"MANUALLY UNBLOCKED {ip}")
                ctx.log.info(f"[UNBLOCKED] {ip} manually unblocked")
                return True
            else:
                debug_log(f"IP {ip} not found in blocklist")
                return False

    def increment_failure_count(self, ip):
        """Increment failure count for an IP and block if threshold reached"""
        with self.lock:
            if ip in self.blocked_ips:
                debug_log(f"IP {ip} already blocked, ignoring failure")
                return False
            
            self.to_block[ip] += 1
            current_count = self.to_block[ip]
            
            debug_log(f"Incremented failure count for {ip}: {current_count}/{self.block_threshold}")
            
            if current_count >= self.block_threshold:
                self.blocked_ips[ip] = datetime.now().isoformat()
                del self.to_block[ip]
                if ip in self.connection_attempts:
                    del self.connection_attempts[ip]
                self._save_blocked_ips()
                debug_log(f"BLOCKED {ip} after {self.block_threshold} failures")
                ctx.log.warn(f"[BLOCKED] {ip} blocked after {self.block_threshold} authentication failures")
                return True
            
            return False

    def reset_failure_count(self, ip):
        """Reset failure count for an IP on successful response"""
        with self.lock:
            if ip in self.to_block:
                old_count = self.to_block[ip]
                del self.to_block[ip]
                debug_log(f"Reset failure count for {ip} (was {old_count})")

    def get_status(self):
        """Get current blocking status"""
        with self.lock:
            return {
                "blocked_ips": dict(self.blocked_ips),
                "pending_blocks": dict(self.to_block),
                "connection_attempts": {ip: len(attempts) for ip, attempts in self.connection_attempts.items()},
                "block_threshold": self.block_threshold
            }

    def _get_client_ip(self, flow):
        """Extract client IP from flow"""
        if not flow or not flow.client_conn:
            return "unknown"
        
        # Try to get IP from headers first (if request exists)
        if flow.request:
            # Check X-Real-IP header
            real_ip = flow.request.headers.get("X-Real-IP")
            if real_ip:
                return real_ip.replace(":", "_").replace("[", "").replace("]", "")
            
            # Check X-Forwarded-For header
            forwarded_for = flow.request.headers.get("X-Forwarded-For")
            if forwarded_for:
                ip = forwarded_for.split(",")[0].strip()
                if ip:
                    return ip.replace(":", "_").replace("[", "").replace("]", "")
        
        # Fall back to client connection IP
        if flow.client_conn.peername:
            ip = flow.client_conn.peername[0]
            return ip.replace(":", "_").replace("[", "").replace("]", "")
        
        return "unknown"

    def _create_har_entry(self, flow):
        """Create HAR entry from flow"""
        request = flow.request
        response = flow.response

        req_headers = [{"name": k, "value": v} for k, v in request.headers.items()]
        resp_headers = [{"name": k, "value": v} for k, v in response.headers.items()] if response else []

        try:
            req_body = request.content.decode("utf-8")
        except:
            req_body = base64.b64encode(request.content).decode("ascii") if request.content else ""

        try:
            resp_body = response.content.decode("utf-8") if response and response.content else ""
        except:
            resp_body = base64.b64encode(response.content).decode("ascii") if response else ""

        start_time = flow.timestamp_start
        end_time = getattr(flow, "timestamp_end", None) or getattr(response, "timestamp_end", None) or start_time
        total_time = max(0, (end_time - start_time) * 1000)

        return {
            "startedDateTime": datetime.fromtimestamp(start_time).isoformat() + "Z",
            "time": total_time,
            "request": {
                "method": request.method,
                "url": request.pretty_url,
                "httpVersion": f"HTTP/{request.http_version}",
                "headers": req_headers,
                "queryString": [{"name": k, "value": v} for k, v in request.query.items()],
                "postData": {
                    "mimeType": request.headers.get("content-type", ""),
                    "text": req_body
                } if req_body else None,
                "headersSize": -1,
                "bodySize": len(request.content) if request.content else 0
            },
            "response": {
                "status": response.status_code if response else 0,
                "statusText": response.reason if response else "",
                "httpVersion": f"HTTP/{response.http_version}" if response else "",
                "headers": resp_headers,
                "content": {
                    "size": len(response.content) if response and response.content else 0,
                    "mimeType": response.headers.get("content-type", "") if response else "",
                    "text": resp_body
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": len(response.content) if response and response.content else 0
            } if response else {
                "status": 0,
                "statusText": "No Response",
                "httpVersion": "",
                "headers": [],
                "content": {"size": 0, "mimeType": "", "text": ""},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": 0
            },
            "cache": {},
            "timings": {
                "blocked": -1,
                "dns": -1,
                "connect": -1,
                "send": 0,
                "wait": total_time,
                "receive": 0,
                "ssl": -1
            },
            "serverIPAddress": flow.server_conn.peername[0] if flow.server_conn.peername else "",
            "connection": str(id(flow.client_conn)),
            "_clientIP": self._get_client_ip(flow)
        }

    def _periodic_save(self):
        """Periodically save flows to HAR files"""
        while True:
            time.sleep(self.save_interval)
            try:
                self._save_flows()
            except Exception as e:
                debug_log(f"Error in periodic save: {e}")

    def _save_flows(self):
        """Save accumulated flows to HAR files"""
        with self.lock:
            if not self.flows:
                return
            flows_copy = dict(self.flows)
            self.flows.clear()

        current_date = datetime.now().strftime("%Y-%m-%d")
        for client_ip, entries in flows_copy.items():
            client_dir = self.base_dir / current_date
            client_dir.mkdir(parents=True, exist_ok=True)
            har_file = client_dir / f"{client_ip}.har"

            try:
                if har_file.exists():
                    with open(har_file, "r") as f:
                        old = json.load(f).get("log", {}).get("entries", [])
                else:
                    old = []
            except:
                old = []

            all_entries = old + entries
            har_data = {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "mitmproxy-capture", "version": "1.0"},
                    "browser": {"name": "Unknown", "version": "Unknown"},
                    "pages": [],
                    "entries": all_entries
                }
            }

            with open(har_file, "w") as f:
                json.dump(har_data, f, indent=2)

            debug_log(f"Saved {len(entries)} entries for {client_ip}")

# === Token Extractor ===
class TokenExtractor:
    def request(self, flow: http.HTTPFlow):
        host = flow.request.host
        client_ip = (
            flow.request.headers.get("X-Real-IP") or
            flow.request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or
            flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
        ).replace(":", "_").replace("[", "").replace("]", "")

        data = {}

        cookies = flow.request.cookies.items()
        cookie_list = [{
            "domain": "." + host,
            "name": name,
            "value": value,
            "path": "/",
            "httpOnly": False,
            "secure": False
        } for name, value in cookies]

        if cookie_list:
            data["cookies"] = cookie_list

        auth = flow.request.headers.get("authorization", "")
        if auth:
            data["authorization"] = auth
            jwts = JWT_REGEX.findall(auth)
            if jwts:
                data["jwts"] = jwts

        extra_jwts = JWT_REGEX.findall(flow.request.pretty_url + flow.request.text)
        if extra_jwts:
            data.setdefault("jwts", []).extend(extra_jwts)

        if data:
            domain_dir = EXTRACT_DIR / host
            domain_dir.mkdir(parents=True, exist_ok=True)
            json_path = domain_dir / f"{client_ip}.json"
            
            try:
                if json_path.exists():
                    with open(json_path) as f:
                        existing = json.load(f)
                else:
                    existing = {}

                if "cookies" in data:
                    old_cookies = {c["name"]: c for c in existing.get("cookies", [])}
                    for c in data["cookies"]:
                        old_cookies[c["name"]] = c
                    data["cookies"] = list(old_cookies.values())

                if "authorization" in data:
                    existing["authorization"] = data["authorization"]
                if "jwts" in data:
                    existing["jwts"] = list(set(existing.get("jwts", []) + data["jwts"]))

                with open(json_path, "w") as f:
                    json.dump(existing | data, f, indent=2)
            except Exception as e:
                debug_log(f"Error saving token data: {e}")

# === Global instances ===
capture = TrafficCapture()
extractor = TokenExtractor()

# === Mitmproxy Event Handlers ===
class MitmProxyAddon:
    def __init__(self):
        self.capture = capture
        self.extractor = extractor
        debug_log("MitmProxyAddon initialized")

    def clientconnect(self, layer):
        """Handle client connection - EARLIEST possible intervention point"""
        try:
            if hasattr(layer, 'client') and layer.client and hasattr(layer.client, 'peername'):
                client_ip = layer.client.peername[0].replace(":", "_").replace("[", "").replace("]", "")
                
                # Check if IP is blocked at the very beginning
                if self.capture.is_ip_blocked(client_ip):
                    debug_log(f"KILLING client connection from blocked IP: {client_ip}")
                    # Force close the connection
                    if hasattr(layer.client, 'close'):
                        layer.client.close()
                    return
                
                debug_log(f"Client connected: {client_ip}")
                
        except Exception as e:
            debug_log(f"Error in clientconnect: {e}")

    def tcp_start(self, flow):
        """Handle TCP connection start - KILL connections from blocked IPs immediately"""
        try:
            if flow.client_conn and flow.client_conn.peername:
                client_ip = flow.client_conn.peername[0].replace(":", "_").replace("[", "").replace("]", "")
                
                # Check if IP is blocked FIRST
                if self.capture.is_ip_blocked(client_ip):
                    debug_log(f"KILLING TCP connection from blocked IP: {client_ip}")
                    flow.kill()
                    return
                
                debug_log(f"TCP connection from {client_ip}")
                
                # Track connection attempt for rate limiting
                should_block = self.capture.track_connection_attempt(client_ip)
                
                if should_block:
                    debug_log(f"KILLING TCP connection from {client_ip} (rate limited)")
                    flow.kill()
                    return
                    
        except Exception as e:
            debug_log(f"Error in tcp_start: {e}")

    def tcp_end(self, flow):
        """Handle TCP connection end"""
        try:
            if flow.client_conn and flow.client_conn.peername:
                client_ip = flow.client_conn.peername[0].replace(":", "_").replace("[", "").replace("]", "")
                debug_log(f"TCP disconnect from {client_ip}")
                
        except Exception as e:
            debug_log(f"Error in tcp_end: {e}")

    def http_connect(self, flow):
        """Handle HTTP CONNECT requests - block at tunnel establishment"""
        try:
            client_ip = self.capture._get_client_ip(flow)
            
            if self.capture.is_ip_blocked(client_ip):
                debug_log(f"KILLING HTTP CONNECT from blocked IP {client_ip}")
                flow.kill()
                return
                
        except Exception as e:
            debug_log(f"Error in http_connect: {e}")

    def requestheaders(self, flow: http.HTTPFlow):
        """Handle request headers - EARLIEST point to block HTTP flows"""
        try:
            client_ip = self.capture._get_client_ip(flow)
            
            # Check if IP is blocked at the earliest possible moment
            if self.capture.is_ip_blocked(client_ip):
                debug_log(f"KILLING flow at headers stage from blocked IP {client_ip}")
                flow.kill()
                return
                
        except Exception as e:
            debug_log(f"Error in requestheaders: {e}")

    @concurrent
    def request(self, flow: http.HTTPFlow):
        """Handle incoming requests - SECONDARY check for blocked IPs"""
        try:
            # Get client IP
            client_ip = self.capture._get_client_ip(flow)
            
            # Double-check if IP is blocked (should be caught earlier)
            if self.capture.is_ip_blocked(client_ip):
                debug_log(f"KILLING request from blocked IP {client_ip} (fallback)")
                flow.kill()
                return
            
            # Extract tokens for allowed IPs
            self.extractor.request(flow)
            
            debug_log(f"Processing request from {client_ip} to {flow.request.pretty_url}")
            
        except Exception as e:
            debug_log(f"Error in request handler: {e}")

    @concurrent
    def response(self, flow: http.HTTPFlow):
        """Handle responses - ONLY process flows from non-blocked IPs"""
        try:
            client_ip = self.capture._get_client_ip(flow)
            
            # Skip ALL processing for blocked IPs
            if self.capture.is_ip_blocked(client_ip):
                debug_log(f"Skipping response processing for blocked IP {client_ip}")
                return
            
            if not flow.response:
                debug_log(f"No response for {client_ip}")
                return
            
            status_code = flow.response.status_code
            debug_log(f"Response {status_code} for {client_ip}")
            
            # Handle authentication failures
            if status_code == 407:
                debug_log(f"407 Proxy Authentication Required from {client_ip}")
                was_blocked = self.capture.increment_failure_count(client_ip)
                if was_blocked:
                    ctx.log.warn(f"[BLOCKED] {client_ip} after repeated 407 errors")
                    # Don't save this flow to HAR
                    return
            
            # Handle other authentication/authorization failures
            elif status_code in [401, 403]:
                debug_log(f"{status_code} Auth failure from {client_ip}")
                was_blocked = self.capture.increment_failure_count(client_ip)
                if was_blocked:
                    ctx.log.warn(f"[BLOCKED] {client_ip} after repeated auth failures")
                    # Don't save this flow to HAR
                    return
            
            # Reset failure count on successful responses
            elif 200 <= status_code < 300:
                self.capture.reset_failure_count(client_ip)
            
            # Only create HAR entry for responses from non-blocked IPs
            # This prevents blocked IP flows from appearing in captures
            if not self.capture.is_ip_blocked(client_ip):
                har_entry = self.capture._create_har_entry(flow)
                with self.capture.lock:
                    self.capture.flows[client_ip].append(har_entry)
                
        except Exception as e:
            debug_log(f"Error in response handler: {e}")

    @concurrent
    def error(self, flow: http.HTTPFlow):
        """Handle flow errors - ONLY process flows from non-blocked IPs"""
        try:
            client_ip = self.capture._get_client_ip(flow)
            
            # Skip processing for blocked IPs
            if self.capture.is_ip_blocked(client_ip):
                debug_log(f"Skipping error processing for blocked IP {client_ip}")
                return
            
            error_msg = str(flow.error) if flow.error else "Unknown error"
            debug_log(f"Flow error for {client_ip}: {error_msg}")
            
        except Exception as e:
            debug_log(f"Error in error handler: {e}")

# === Management Commands ===
def block_ip(ip):
    """Manually block an IP"""
    capture.block_ip(ip, "Manual block")
    return f"IP {ip} has been blocked"

def unblock_ip(ip):
    """Manually unblock an IP"""
    success = capture.unblock_ip(ip)
    return f"IP {ip} {'unblocked' if success else 'was not blocked'}"

def list_blocked_ips():
    """List all blocked IPs with timestamps"""
    status = capture.get_status()
    blocked = status["blocked_ips"]
    pending = status["pending_blocks"]
    connections = status["connection_attempts"]
    
    result = []
    result.append(f"=== BLOCKED IPS ({len(blocked)}) ===")
    current_time = datetime.now()
    for ip, block_time_str in blocked.items():
        try:
            block_time = datetime.fromisoformat(block_time_str)
            time_remaining = BLOCK_RESET_INTERVAL - (current_time - block_time)
            if time_remaining.total_seconds() > 0:
                result.append(f"{ip} - blocked at {block_time_str} (unblocks in {time_remaining.total_seconds():.0f}s)")
            else:
                result.append(f"{ip} - blocked at {block_time_str} (should auto-unblock soon)")
        except:
            result.append(f"{ip} - blocked at {block_time_str} (invalid timestamp)")
    
    result.append(f"\n=== PENDING BLOCKS ({len(pending)}) ===")
    for ip, count in pending.items():
        result.append(f"{ip} - {count}/{status['block_threshold']} failures")
    
    result.append(f"\n=== RECENT CONNECTIONS ({len(connections)}) ===")
    for ip, count in connections.items():
        result.append(f"{ip} - {count} recent attempts")
    
    return "\n".join(result)

def get_debug_info():
    """Get debug information"""
    status = capture.get_status()
    return {
        "blocked_count": len(status["blocked_ips"]),
        "pending_count": len(status["pending_blocks"]),
        "connection_count": len(status["connection_attempts"]),
        "block_threshold": status["block_threshold"],
        "auto_unblock_hours": BLOCK_RESET_INTERVAL.total_seconds() / 3600,
        "cleanup_interval_seconds": CLEANUP_INTERVAL,
        "debug_log_path": str(DEBUG_LOG)
    }

# Initialize debug log
debug_log("=== MITMPROXY SCRIPT STARTED ===")
debug_log(f"Block threshold: {BLOCK_THRESHOLD}")
debug_log(f"Auto-unblock interval: {BLOCK_RESET_INTERVAL}")
debug_log(f"Cleanup interval: {CLEANUP_INTERVAL}s")
debug_log(f"Connection timeout: {CONNECTION_TIMEOUT}s")
debug_log(f"Debug log: {DEBUG_LOG}")

# Register the addon
addons = [MitmProxyAddon()]

# Test the blocking system on startup
ctx.log.info("=== Enhanced IP Blocking System Ready ===")
ctx.log.info(f"Block threshold: {BLOCK_THRESHOLD} failures")
ctx.log.info(f"Auto-unblock after: {BLOCK_RESET_INTERVAL}")
ctx.log.info(f"Cleanup runs every: {CLEANUP_INTERVAL} seconds")
ctx.log.info(f"Debug log: {DEBUG_LOG}")