# Reticulum Gateway

A production-grade generic TCP tunnel that bridges Reticulum to the internet. Routes **any protocol** through Reticulum with full bidirectional streaming, featuring enterprise-level security and monitoring.

## What It Does

Runs on a machine with internet access and provides a gateway service on the Reticulum network. Remote clients can connect and request tunnels to any destination (host:port) on the internet or other Reticulum services.

## Protocols Supported

- **HTTP/HTTPS** - Web browsing
- **SSH** - Remote shell access
- **DNS** - Domain name resolution
- **SMTP/POP3/IMAP** - Email
- **Any TCP-based protocol** - Full passthrough

## Quick Start

### Server Setup (on internet-connected machine)

```bash
python gateway.py
```

Output shows:
```
Destination hash: 15:4d:e5:7d:ef:b0:4f:7e:4f:e3:78:77:a5:eb:54:1e
Reticulum Gateway announced on Reticulum
```

Share the destination hash with clients.

### Custom Identity Path

```bash
python gateway.py --identity /path/to/identity
```

## Architecture

```
Client (Reticulum network)
    ↓ RNS.Link + RNS.Buffer
Tunnel Request: "TUNNEL example.com 443"
    ↓
Reticulum Gateway
    ↓ TCP connection
Internet/Services: example.com:443
    ↓ bidirectional relay
```

## Tunnel Protocol

Clients send:
```
TUNNEL <hostname> <port>\r\n
```

Server responds:
```
OK\r\n
```

Then relays all subsequent data bidirectionally.

## Features

### Core Tunnel Features
- ✅ Generic protocol support (not HTTP-specific)
- ✅ Full bidirectional streaming via RNS.Buffer
- ✅ Multiple concurrent clients
- ✅ Automatic path discovery
- ✅ Persistent identity

### Security & Monitoring
- ✅ Rate limiting (global, per-user, per-connection)
- ✅ Rules engine with whitelist/blacklist
- ✅ Audit logging (security events)
- ✅ DDoS protection
- ✅ Role-based access control (RBAC)
- ✅ Bandwidth monitoring

## Limitations

- TCP only (UDP tunneling not yet implemented)
- Single tunnel per client link (multiplex multiple streams via higher-level protocol)

## Configuration

The gateway is configured via `config.yaml` with support for:

```bash
# Run with default config.yaml
python gateway.py

# Custom config file
python gateway.py --config /path/to/config.yaml

# Custom identity file
python gateway.py --identity ~/.reticulum/gateway_id

# View help
python gateway.py --help
```

### Configuration Features

- **Rate Limiting** - Set global and per-user request limits
- **Rules Engine** - Define whitelist/blacklist rules for destinations
- **Audit Logging** - Log security events to `gateway_audit.log`
- **Authentication** - Support for multiple auth methods
- **Role-based Access Control** - User-specific tunnel rules

## Use Cases

1. **Gateway to internet** - Provide internet access to Reticulum network
2. **SSH gateway** - Remote Reticulum users can SSH to internet servers
3. **DNS resolver** - Route DNS queries through Reticulum
4. **Email bridge** - SMTP/IMAP access for Reticulum users
5. **Generic tunnel** - Any TCP service accessed via Reticulum
6. **Reticulum service bridge** - Connect to other Reticulum services

## See Also

- **reticulum-client** - Client interface for accessing this gateway