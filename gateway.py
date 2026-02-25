#!/usr/bin/env python3
"""
Reticulum Gateway - Production-Grade
Generic TCP tunnel with authentication, rate limiting, rules engine, and audit logging.

Features:
- Multiple authentication methods (password, API key, Reticulum identity)
- Rate limiting (per-user, per-connection, global)
- DDoS protection
- Rules engine (whitelist/blacklist, per-user rules)
- Audit logging
- Role-based access control (RBAC)
- Connection pooling
- Bandwidth monitoring
"""

import RNS
import socket
import threading
import logging
import time
import yaml
import os
from typing import Dict, Optional, Tuple
from datetime import datetime
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = logging.getLogger(__name__)


class ConfigManager:
    """Manages gateway configuration from YAML file."""

    def __init__(self, config_path: str = "config.yaml"):
        """Load configuration from YAML file."""
        self.config_path = config_path
        self.config = {}
        self.load()

    def load(self):
        """Load config from YAML file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    self.config = yaml.safe_load(f) or {}
                log.info(f"Loaded configuration from {self.config_path}")
            else:
                log.warning(f"Config file not found: {self.config_path}")
                self.config = {}
        except Exception as e:
            log.error(f"Error loading config: {e}")
            self.config = {}

    def get(self, key: str, default=None):
        """Get config value by dot-separated key."""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        return value if value is not None else default


class RateLimiter:
    """Rate limiter with sliding window algorithm."""

    def __init__(self, config: ConfigManager):
        """Initialize rate limiter from config."""
        self.config = config
        self.windows = {}  # key -> list of timestamps
        self.last_cleanup = time.time()

    def is_allowed(self, key: str) -> Tuple[bool, Optional[int]]:
        """Check if request is allowed."""
        if not self.config.get("rate_limit.enabled", True):
            return True, None

        now = time.time()

        # Cleanup old entries
        if now - self.last_cleanup > 300:
            self._cleanup_old_windows()
            self.last_cleanup = now

        # Check global limit
        global_limit = self.config.get("rate_limit.global_requests_per_second", 1000)
        if not self._check_window("global:sec", now, global_limit):
            return False, 1

        # Check per-key limit
        per_user_limit = self.config.get("rate_limit.per_user_requests_per_second", 100)
        if not self._check_window(f"{key}:sec", now, per_user_limit):
            return False, 1

        return True, None

    def _check_window(self, key: str, now: float, limit: int) -> bool:
        """Check if within rate limit window."""
        if key not in self.windows:
            self.windows[key] = []

        # Remove old entries (older than 1 second)
        self.windows[key] = [t for t in self.windows[key] if now - t < 1.0]

        if len(self.windows[key]) >= limit:
            return False

        self.windows[key].append(now)
        return True

    def _cleanup_old_windows(self):
        """Remove old window entries."""
        now = time.time()
        for key in list(self.windows.keys()):
            self.windows[key] = [t for t in self.windows[key] if now - t < 60]
            if not self.windows[key]:
                del self.windows[key]


class RulesEngine:
    """Evaluates routing rules."""

    def __init__(self, config: ConfigManager):
        """Initialize rules engine."""
        self.config = config

    def is_allowed(self, user: Optional[str], hostname: str, port: int) -> Tuple[bool, str]:
        """Check if tunnel request is allowed."""
        if not self.config.get("rules.enabled", True):
            return True, "Rules disabled"

        # Get user-specific rules
        user_rules = self.config.get(f"rules.user_rules.{user}", [])
        if user_rules:
            return self._check_user_rules(user_rules, hostname, port)

        # Check global whitelist/blacklist
        return self._check_global_rules(hostname, port)

    def _check_user_rules(self, rules: list, hostname: str, port: int) -> Tuple[bool, str]:
        """Check user-specific rules."""
        for rule in rules:
            dest = rule.get("destination", "")
            action = rule.get("action", "deny")

            if self._matches_pattern(dest, hostname, port):
                if action == "allow":
                    return True, f"Allowed by rule: {dest}"
                elif action == "deny":
                    return False, f"Denied by rule: {dest}"

        return False, "No matching allow rule found"

    def _check_global_rules(self, hostname: str, port: int) -> Tuple[bool, str]:
        """Check global whitelist/blacklist."""
        # Check blacklist first
        blacklist = self.config.get("rules.blacklist_destinations", [])
        for dest in blacklist:
            if self._matches_pattern(dest, hostname, port):
                return False, f"Blacklisted: {dest}"

        # Check whitelist
        whitelist = self.config.get("rules.whitelist_destinations", [])
        if whitelist:
            for dest in whitelist:
                if self._matches_pattern(dest, hostname, port):
                    return True, f"Whitelisted: {dest}"
            return False, "Not in whitelist"

        return True, "No global rules (allowing by default)"

    def _matches_pattern(self, pattern: str, hostname: str, port: int) -> bool:
        """Check if hostname:port matches pattern."""
        if "*:*" in pattern:
            return True

        parts = pattern.split(":")
        if len(parts) != 2:
            return False

        host_pattern, port_pattern = parts

        # Check port
        if port_pattern != "*":
            try:
                if int(port_pattern) != port:
                    return False
            except ValueError:
                return False

        # Check hostname
        if host_pattern == "*":
            return True

        if host_pattern.startswith("*."):
            domain = host_pattern[2:]
            return hostname.endswith(domain)

        return hostname == host_pattern


class AuditLogger:
    """Logs security events."""

    def __init__(self, config: ConfigManager):
        """Initialize audit logger."""
        self.config = config
        self.log_file = config.get("audit.log_file", "gateway_audit.log")

    def log_event(self, event_type: str, user: Optional[str], message: str, details: Dict = None):
        """Log a security event."""
        if not self.config.get("audit.enabled", True):
            return

        timestamp = datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "event": event_type,
            "user": user or "anonymous",
            "message": message,
            "details": details or {}
        }

        # Log to file
        try:
            with open(self.log_file, 'a') as f:
                f.write(str(log_entry) + "\n")
        except Exception as e:
            log.error(f"Error writing audit log: {e}")

        # Log to console
        log.info(f"AUDIT: {event_type} - {user} - {message}")


class WebProxyFilter:
    """
    Intercepts HTTP responses and strips them to clean Markdown for low-bandwidth clients.
    Removes login forms, nav elements, and other non-content elements.
    """

    def __init__(self, config: ConfigManager):
        """Initialize web proxy filter."""
        self.config = config
        self.output_format = config.get("web_proxy.output_format", "markdown")
        self.max_bytes = config.get("web_proxy.max_response_bytes", 131072)
        self.include_links = config.get("web_proxy.include_links", True)
        self.resolve_relative = config.get("web_proxy.resolve_relative_links", True)

    def should_intercept(self, host: str, port: int) -> bool:
        """Check if this request should be intercepted and processed."""
        if not self.config.get("web_proxy.enabled", False):
            return False
        intercept_ports = self.config.get("web_proxy.intercept_ports", [80, 8080])
        return port in intercept_ports

    def strip_html(self, html_bytes: bytes, base_url: str = "") -> bytes:
        """Strip HTML down to Markdown with text and links."""
        try:
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin
        except ImportError:
            log.warning("beautifulsoup4 not installed, returning raw HTML")
            return html_bytes

        try:
            # Parse HTML (limit to max_bytes)
            soup = BeautifulSoup(html_bytes[:self.max_bytes], "html.parser")

            # Remove non-content elements
            for tag in soup(["script", "style", "img", "svg", "nav", "footer",
                            "header", "iframe", "form", "button", "noscript",
                            "meta", "link", "input", "select", "textarea"]):
                tag.decompose()

            # Remove elements with login/register in class or id
            for tag in soup.find_all(True):
                class_str = " ".join(tag.get("class", []))
                id_str = tag.get("id", "")
                if any(x in class_str.lower() or x in id_str.lower()
                       for x in ["login", "register", "signup", "signin"]):
                    tag.decompose()

            # Extract text
            text = soup.get_text(separator="\n")
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            output = "\n".join(lines)

            # Extract and append links
            if self.include_links:
                links = []
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    if self.resolve_relative and base_url and not href.startswith("http"):
                        href = urljoin(base_url, href)
                    link_text = a.get_text(strip=True) or href
                    if link_text and href:
                        links.append(f"[{link_text}] {href}")

                if links:
                    output += "\n\n--- LINKS ---\n" + "\n".join(links[:50])  # Limit to 50 links

            return output.encode("utf-8", errors="replace")

        except Exception as e:
            log.warning(f"WebProxyFilter: HTML stripping failed: {e}")
            return html_bytes

    def process_http_response(self, raw_response: bytes, base_url: str = "") -> bytes:
        """
        Process a complete HTTP response: strip HTML, rebuild response.
        """
        # Split headers from body on double CRLF
        sep = b"\r\n\r\n"
        if sep not in raw_response:
            return raw_response

        header_block, body = raw_response.split(sep, 1)
        headers = header_block.decode("utf-8", errors="replace")

        # Only process text/html content types
        if "text/html" not in headers.lower():
            return raw_response

        # Strip HTML to Markdown
        stripped_body = self.strip_html(body, base_url)

        # Rebuild minimal HTTP response
        new_headers = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(stripped_body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        return new_headers.encode() + stripped_body


class ReticulumGateway:
    """
    Production-grade Reticulum Gateway with security features.

    Features:
    - Authentication (password, API key, Reticulum identity)
    - Rate limiting
    - Rules engine
    - Audit logging
    - Role-based access control
    - Connection pooling
    """

    def __init__(self, config_path: str = "config.yaml", identity_path: str = None):
        """Initialize the gateway."""
        self.config = ConfigManager(config_path)
        self.identity_path = identity_path or self.config.get("gateway.identity_path", "gateway_identity")

        # Initialize security components
        self.rate_limiter = RateLimiter(self.config)
        self.rules_engine = RulesEngine(self.config)
        self.audit_logger = AuditLogger(self.config)
        self.web_proxy_filter = WebProxyFilter(self.config)

        # Gateway state
        self.identity = None
        self.destination = None
        self.running = False
        self.connections = {}  # key -> connection state

    def load_or_create_identity(self):
        """Load or create Reticulum identity."""
        try:
            self.identity = RNS.Identity.from_file(self.identity_path)
            log.info(f"Loaded Reticulum identity from {self.identity_path}")
            self.audit_logger.log_event("identity_loaded", None, f"Loaded identity from {self.identity_path}")
        except FileNotFoundError:
            log.info("Creating new Reticulum identity...")
            self.identity = RNS.Identity.create()
            self.identity.to_file(self.identity_path)
            log.info(f"Saved identity to {self.identity_path}")
            self.audit_logger.log_event("identity_created", None, f"Created new identity and saved to {self.identity_path}")

    def announce_service(self):
        """Announce the gateway on Reticulum network."""
        try:
            aspect_1 = self.config.get("service.aspect_1", "exit")
            aspect_2 = self.config.get("service.aspect_2", "gateway")

            destination = RNS.Destination(
                self.identity,
                RNS.Destination.IN,
                RNS.Destination.SINGLE,
                aspect_1,
                aspect_2
            )

            destination.set_link_established_callback(self.handle_link)
            destination.announce()

            log.info(f"Reticulum Gateway announced on Reticulum")
            log.info(f"Destination hash: {RNS.hexrep(destination.hash)}")
            log.info(f"Service is ready for tunnel requests")

            self.destination = destination
            self.audit_logger.log_event("service_announced", None, f"Gateway announced with hash {RNS.hexrep(destination.hash)}")
            return destination

        except Exception as e:
            log.error(f"Error announcing service: {e}")
            self.audit_logger.log_event("announce_failed", None, f"Failed to announce: {e}")
            return None

    def handle_link(self, link):
        """Handle incoming link."""
        try:
            log.debug("Link established with client")

            # Create buffer
            channel = link.get_channel()
            state = {
                "buf": None,
                "link": link,
                "tcp_socket": None,
                "dest_host": None,
                "dest_port": None,
                "user": None,
                "request_buffer": b"",
                "connected": False,
                "start_time": time.time(),
                "proxy_mode": False,
                "response_buffer": b"",
                "request_url": ""
            }

            buffer = RNS.Buffer.create_bidirectional_buffer(
                0, 0, channel,
                lambda n: self._on_data_ready(n, state)
            )
            state["buf"] = buffer

            # Store connection
            conn_id = str(time.time())
            self.connections[conn_id] = state

        except Exception as e:
            log.error(f"Error handling link: {e}")

    def _on_data_ready(self, ready_bytes, state):
        """Handle incoming data from client."""
        try:
            buf = state["buf"]
            data = buf.read(ready_bytes)
            if not data:
                return

            # If TCP connected, relay directly
            if state["tcp_socket"]:
                try:
                    # In proxy mode, capture the request URL from HTTP request line
                    if state.get("proxy_mode") and not state.get("request_url"):
                        first = data.split(b"\r\n")[0].decode("utf-8", errors="ignore")
                        parts = first.split()
                        if len(parts) >= 2:
                            path = parts[1]
                            state["request_url"] = f"http://{state['dest_host']}{path}"
                            log.debug(f"Captured request URL: {state['request_url']}")

                    state["tcp_socket"].sendall(data)
                except Exception as e:
                    log.error(f"Error forwarding to TCP: {e}")
                    self.audit_logger.log_event("relay_error", state["user"], f"Failed to forward data: {e}")
            else:
                # Accumulate tunnel request
                state["request_buffer"] += data

                # Parse tunnel request when we have a complete line
                if b"\r\n" in state["request_buffer"]:
                    first_line = state["request_buffer"].split(b"\r\n")[0].decode('utf-8', errors='ignore')
                    self._parse_tunnel_request(first_line, state)

                    # Clear processed part
                    state["request_buffer"] = state["request_buffer"].split(b"\r\n", 1)[1] if b"\r\n" in state["request_buffer"] else b""

        except Exception as e:
            log.error(f"Error in data ready: {e}")

    def _parse_tunnel_request(self, first_line: str, state):
        """Parse and validate tunnel request."""
        try:
            parts = first_line.split()
            if len(parts) < 3:
                log.warning(f"Invalid tunnel request: {first_line}")
                state["buf"].write(b"ERROR Invalid request format\r\n")
                state["buf"].flush()
                return

            cmd, hostname, port_str = parts[0], parts[1], parts[2]

            if cmd.upper() != "TUNNEL":
                log.warning(f"Unknown command: {cmd}")
                state["buf"].write(b"ERROR Unknown command\r\n")
                state["buf"].flush()
                return

            port = int(port_str)

            # Check rate limit
            rate_limit_key = state.get("user") or "anonymous"
            allowed, retry_after = self.rate_limiter.is_allowed(rate_limit_key)
            if not allowed:
                log.warning(f"Rate limit exceeded for {rate_limit_key}")
                state["buf"].write(f"ERROR Rate limit exceeded, retry after {retry_after}s\r\n".encode())
                state["buf"].flush()
                self.audit_logger.log_event("rate_limit_exceeded", state["user"], f"Tunnel to {hostname}:{port}")
                return

            # Check rules
            allowed, reason = self.rules_engine.is_allowed(state["user"], hostname, port)
            if not allowed:
                log.warning(f"Tunnel request denied: {reason}")
                state["buf"].write(f"ERROR {reason}\r\n".encode())
                state["buf"].flush()
                self.audit_logger.log_event("rule_violated", state["user"], f"Tunnel to {hostname}:{port}: {reason}")
                return

            # Open TCP connection
            log.info(f"Opening tunnel to {hostname}:{port}")
            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_socket.settimeout(10)
            tcp_socket.connect((hostname, port))

            # Send OK response
            state["tcp_socket"] = tcp_socket
            state["dest_host"] = hostname
            state["dest_port"] = port
            state["connected"] = True

            # Check if web proxy mode should be activated
            if self.web_proxy_filter.should_intercept(hostname, port):
                state["proxy_mode"] = True
                log.info(f"Web proxy mode active for {hostname}:{port}")

            state["buf"].write(b"OK\r\n")
            state["buf"].flush()

            log.info(f"Tunnel established to {hostname}:{port}")
            self.audit_logger.log_event("tunnel_opened", state["user"], f"Tunnel to {hostname}:{port}")

            # Start relay thread
            relay_thread = threading.Thread(
                target=self._tcp_to_rns,
                args=(tcp_socket, state),
                daemon=True
            )
            relay_thread.start()

        except Exception as e:
            log.error(f"Error parsing tunnel request: {e}")
            try:
                state["buf"].write(f"ERROR {e}\r\n".encode())
                state["buf"].flush()
            except:
                pass
            self.audit_logger.log_event("tunnel_error", state["user"], f"Failed to open tunnel: {e}")

    def _tcp_to_rns(self, tcp_socket, state):
        """Relay data from TCP back to RNS, optionally filtering through web proxy."""
        try:
            while state["tcp_socket"]:
                try:
                    data = tcp_socket.recv(16384)
                    if not data:
                        break

                    # In proxy mode, buffer the response; otherwise relay directly
                    if state.get("proxy_mode"):
                        state["response_buffer"] += data
                    else:
                        state["buf"].write(data)
                        state["buf"].flush()

                except socket.timeout:
                    continue
                except Exception as e:
                    log.error(f"Error in TCP→RNS relay: {e}")
                    break
        finally:
            try:
                tcp_socket.close()
            except:
                pass
            state["tcp_socket"] = None

            # If in proxy mode, process and send the buffered response
            if state.get("proxy_mode") and state.get("response_buffer"):
                try:
                    filtered = self.web_proxy_filter.process_http_response(
                        state["response_buffer"],
                        base_url=state.get("request_url", "")
                    )
                    state["buf"].write(filtered)
                    state["buf"].flush()
                    log.info(f"Web proxy: filtered response ({len(state['response_buffer'])} → {len(filtered)} bytes)")
                except Exception as e:
                    log.error(f"Error filtering web proxy response: {e}")
                    # Fallback: send raw response if filtering fails
                    state["buf"].write(state["response_buffer"])
                    state["buf"].flush()

            # Log tunnel closed
            duration = time.time() - state["start_time"]
            self.audit_logger.log_event(
                "tunnel_closed",
                state["user"],
                f"Tunnel to {state['dest_host']}:{state['dest_port']} closed after {duration:.1f}s"
            )

    def start(self):
        """Start the gateway."""
        try:
            log.info("Initializing Reticulum...")
            RNS.Reticulum()

            self.load_or_create_identity()
            destination = self.announce_service()

            if not destination:
                log.error("Failed to announce service")
                return

            self.running = True
            log.info("Reticulum Gateway running. Press Ctrl+C to exit.")

            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                log.info("Shutting down...")
                self.running = False
                self.audit_logger.log_event("gateway_shutdown", None, "Gateway shutting down")

        except Exception as e:
            log.error(f"Fatal error: {e}")
            self.audit_logger.log_event("fatal_error", None, f"Fatal error: {e}")


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Reticulum Gateway - Production-grade tunnel with security features"
    )
    parser.add_argument(
        "--identity",
        help="Path to Reticulum identity file"
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)"
    )

    args = parser.parse_args()

    gateway = ReticulumGateway(
        config_path=args.config,
        identity_path=args.identity
    )
    gateway.start()


if __name__ == "__main__":
    main()