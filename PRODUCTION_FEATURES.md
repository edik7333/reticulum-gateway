# Reticulum Gateway - Production Features

## Overview

The enhanced gateway (`gateway_enhanced.py`) includes enterprise-grade security and management features.

## Features Included

### 1. Configuration Management ✅
- YAML-based configuration (`config.yaml`)
- All settings centralized and documented
- Easy to modify without code changes
- Supports reload without restart (future enhancement)

### 2. Authentication ✅
- Multiple auth methods (password, API key, Reticulum identity)
- User management system
- Session management
- Failed attempt tracking and account lockout
- Configurable users with roles

**Configuration:**
```yaml
auth:
  enabled: true
  method: "password"  # or "api_key", "reticulum_identity"
  users:
    admin:
      password_hash: "$2b$12$..."
      roles: ["admin"]
```

### 3. Rate Limiting ✅
- Global rate limits
- Per-user limits
- Per-connection limits
- Sliding window algorithm
- Burst handling (configurable multiplier)
- Automatic cleanup of old entries

**Configuration:**
```yaml
rate_limit:
  enabled: true
  global_requests_per_second: 1000
  per_user_requests_per_second: 100
  per_user_requests_per_minute: 6000
  burst_multiplier: 1.5
```

### 4. Rules Engine ✅
- Whitelist destinations (what's allowed)
- Blacklist destinations (what's blocked)
- Per-user routing rules
- Pattern matching (wildcards, CIDR notation)
- Action-based rules (allow/deny)

**Configuration:**
```yaml
rules:
  enabled: true
  user_rules:
    admin:
      - destination: "*:*"
        action: "allow"

    limited:
      - destination: "*.example.com:443"
        action: "allow"
      - destination: "*:*"
        action: "deny"
```

### 5. DDoS Protection ✅
- Connection spike detection
- Bandwidth spike detection
- Auto-blocking on violations
- Configurable thresholds

**Configuration:**
```yaml
ddos_protection:
  enabled: true
  connection_spike_threshold: 50
  bandwidth_spike_threshold: 1000
  auto_block_on_violation: false
```

### 6. Audit Logging ✅
- Logs all security events
- Structured logging (timestamp, user, event type, details)
- Configurable retention
- Per-event control

**Events logged:**
- auth_success / auth_failure
- connection_opened / connection_closed
- rate_limit_exceeded
- permission_denied
- rule_violated
- tunnel_opened / tunnel_closed
- identity_created / identity_loaded
- service_announced
- fatal_error

### 7. Role-Based Access Control (RBAC) ✅
- Define roles with permissions
- Assign users to roles
- Fine-grained permissions
- Permission-based route decisions

**Configuration:**
```yaml
roles:
  admin:
    description: "Full access"
    permissions:
      - "tunnel:*"
      - "manage:*"

  user:
    description: "Normal user"
    permissions:
      - "tunnel:*"

  limited:
    description: "Limited access"
    permissions:
      - "tunnel:http"
      - "tunnel:https"
```

### 8. Connection Pooling ✅
- Track active connections
- Per-user connection limits
- Global connection limits
- Idle timeout
- Connection cleanup

**Configuration:**
```yaml
connection_pool:
  enabled: true
  max_connections_per_user: 10
  max_total_connections: 1000
  idle_timeout: 300
```

### 9. Bandwidth Monitoring ✅
- Per-connection bandwidth tracking
- Per-user bandwidth limits
- Global bandwidth limits
- Real-time monitoring

**Configuration:**
```yaml
connection_pool:
  per_connection_bandwidth_mbps: 100
```

## Usage

### Basic Usage (No Security)
```bash
python gateway_enhanced.py
```

### With Custom Config
```bash
python gateway_enhanced.py --config /path/to/config.yaml
```

### With Custom Identity
```bash
python gateway_enhanced.py --identity /path/to/identity
```

## Configuration Examples

### Example 1: Open Gateway (No Auth)
```yaml
auth:
  enabled: false

rules:
  enabled: false

rate_limit:
  enabled: false
```

### Example 2: Restricted Gateway (Limited Users)
```yaml
auth:
  enabled: true
  method: "password"
  users:
    admin:
      password_hash: "..."
      roles: ["admin"]

rules:
  enabled: true
  whitelist_destinations:
    - "*.google.com:443"
    - "*.github.com:443"
```

### Example 3: Enterprise Gateway (Full Security)
```yaml
auth:
  enabled: true
  method: "password"
  max_failed_attempts: 5
  lockout_duration: 900

rate_limit:
  enabled: true
  global_requests_per_second: 1000
  per_user_requests_per_second: 100

ddos_protection:
  enabled: true
  auto_block_on_violation: true

audit:
  enabled: true
  retention_days: 30

connection_pool:
  max_connections_per_user: 10
```

## File Structure

```
reticulum-gateway/
├── gateway.py                (Original simple version)
├── gateway_enhanced.py       (Production version with features)
├── config.yaml              (Configuration template)
├── gateway_audit.log        (Audit log file - auto-created)
└── README.md
```

## Security Best Practices

1. **Change default passwords** - Use bcrypt-hashed passwords
2. **Enable audit logging** - Track all access
3. **Use whitelisting** - Default deny, explicitly allow
4. **Enable rate limiting** - Prevent abuse
5. **Monitor audit logs** - Check for suspicious activity
6. **Regular backups** - Back up identity and config
7. **Update regularly** - Keep up with security patches

## Performance Considerations

- Rate limiter: O(1) per request
- Rules engine: O(n) where n = number of rules per user
- Audit logging: Non-blocking, async where possible
- Connection tracking: O(1) lookups

## Future Enhancements

- [ ] Dynamic config reload (no restart)
- [ ] Web dashboard for monitoring
- [ ] Advanced anomaly detection
- [ ] TLS encryption between gateway and client
- [ ] API key rotation
- [ ] OAuth2 integration
- [ ] Load balancing support
- [ ] Geo-blocking capabilities

## Troubleshooting

### Tunnel requests failing
Check:
1. Authentication enabled/disabled in config
2. Rate limits not exceeded
3. Rules allow the destination
4. Audit log for error details

### Performance issues
- Increase rate limits
- Reduce audit logging verbosity
- Check rules engine for slow patterns
- Monitor bandwidth usage

### Connection issues
- Check `gateway_audit.log` for errors
- Verify config syntax (YAML)
- Check Reticulum paths with `rnstatus`

## License

Same as Reticulum Gateway main project