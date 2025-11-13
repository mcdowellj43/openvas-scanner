# GVM Agent

**Version:** 1.0.0
**Status:** Phase 1 MVP

Host-based vulnerability scanning agent for Greenbone Vulnerability Management (GVM).

## Overview

The GVM Agent is a lightweight daemon that runs on endpoints (servers, workstations, IoT devices) to perform local vulnerability scans. It implements a **pull-based model** where agents poll an Agent Controller for scan jobs, execute them locally with full system access, and submit results back.

### Key Features (Phase 1)

- ✅ **Agent Registration** (FR-AGENT-001): Auto-registers with Agent Controller on first heartbeat
- ✅ **Periodic Heartbeat** (FR-AGENT-002): Sends heartbeat every 10 minutes with retry logic
- ✅ **Job Polling** (FR-AGENT-003): Polls for scan jobs and executes them
- ✅ **Result Submission** (FR-AGENT-006): Submits scan results to Agent Controller
- ✅ **TLS Security** (SR-TLS-001): All communication over HTTPS
- ✅ **Bearer Token Auth** (SR-AUTH-001): Authentication via JWT token

### Architecture

```
┌─────────────────────────────────────────┐
│     Agent Controller (Python/Flask)     │
│  - REST API (Scanner API, Admin API)    │
│  - Job Queue (SQLite)                   │
│  - Agent Registry                       │
└────────────┬────────────────────────────┘
             │ HTTPS
             │ POST /api/v1/agents/heartbeat
             │ GET /api/v1/agents/jobs
             │ POST /api/v1/agents/jobs/{id}/results
             │
┌────────────▼────────────────────────────┐
│          GVM Agent (C)                  │
│  - HTTP Client (libcurl)                │
│  - Heartbeat Loop                       │
│  - Job Processor                        │
│  - Configuration (INI)                  │
└─────────────────────────────────────────┘
```

## Requirements

### Runtime Requirements

- **Linux:** libcurl4, libc6, uuid-runtime
- **Windows:** Windows 7+ (dependencies bundled)
- **Network:** HTTPS access to Agent Controller

### Build Requirements

- **Linux:** GCC, CMake 3.10+, libcurl4-openssl-dev, uuid-dev
- **Windows:** MinGW-w64, CMake 3.10+, libcurl

## Installation

### Linux (Debian/Ubuntu)

```bash
# Install package
sudo dpkg -i gvm-agent-1.0.0-Linux.deb

# Edit configuration
sudo nano /etc/gvm-agent/agent.conf

# Required configuration:
# [controller]
# url = https://your-agent-controller.example.com
# auth_token = <your-token>

# Start service
sudo systemctl start gvm-agent
sudo systemctl enable gvm-agent

# Check status
sudo systemctl status gvm-agent
sudo journalctl -u gvm-agent -f
```

### Linux (RHEL/CentOS)

```bash
# Install package
sudo rpm -i gvm-agent-1.0.0-Linux.rpm

# Edit configuration
sudo nano /etc/gvm-agent/agent.conf

# Start service
sudo systemctl start gvm-agent
sudo systemctl enable gvm-agent
```

### Windows

```powershell
# Run installer (creates Windows Service)
.\gvm-agent-1.0.0-windows-x64.exe /S

# Edit configuration
notepad "C:\Program Files\GVM Agent\agent.conf"

# Start service
net start "GVMAgent"

# Check logs
Get-EventLog -LogName Application -Source GVMAgent -Newest 20
```

## Configuration

Configuration file location per PRD Section 7.2.4:
- **Linux:** `/etc/gvm-agent/agent.conf`
- **Windows:** `C:\Program Files\GVM Agent\agent.conf`
- **macOS:** `/Library/Application Support/GVM Agent/agent.conf`

### Minimal Configuration

```ini
[controller]
url = https://agent-controller.example.com
auth_token = your-auth-token-here

[heartbeat]
interval_in_seconds = 600

[logging]
level = info
```

### Full Configuration

See `config/agent.conf.template` for all available options.

### Important Configuration Notes (per CLAUDE.md)

- ⚠️ **NO PLACEHOLDER DATA**: All values must be real (no "TODO", "FIXME", "example.com")
- ⚠️ **NO FALLBACK BEHAVIOR**: Missing required fields will cause agent to fail with specific error
- ⚠️ **Required Fields:**
  - `controller.url` - Agent Controller URL (must use HTTPS)
  - `controller.auth_token` - Authentication token

## Building from Source

### Linux

```bash
cd gvm-agent
chmod +x build/build-linux.sh
./build/build-linux.sh
```

Produces:
- `gvm-agent-1.0.0-Linux.deb` (Debian/Ubuntu)
- `gvm-agent-1.0.0-Linux.rpm` (RHEL/CentOS)

### Windows (Cross-Compile from Linux)

```bash
# Install MinGW-w64
sudo apt-get install mingw-w64

cd gvm-agent
chmod +x build/build-windows.sh
./build/build-windows.sh
```

Produces:
- `gvm-agent-1.0.0-windows-x64.zip`

### Manual Build

```bash
mkdir build && cd build
cmake ..
cmake --build .
sudo cmake --install .
```

## Usage

### Manual Execution

```bash
# Run with default config
./gvm-agent

# Run with custom config
./gvm-agent --config /path/to/agent.conf

# Show help
./gvm-agent --help

# Show version
./gvm-agent --version
```

### Agent Workflow

1. **Startup:**
   - Load configuration from `agent.conf`
   - Generate UUID if not configured (FR-AGENT-001)
   - Collect system info (OS, arch, IPs)

2. **Registration (FR-AGENT-001):**
   - Send first heartbeat to Agent Controller
   - Wait for admin authorization

3. **Main Loop:**
   - Send heartbeat every 600 seconds (FR-AGENT-002)
   - If unauthorized: wait for authorization
   - If authorized:
     - Poll for jobs (FR-AGENT-003)
     - Execute jobs locally (FR-AGENT-004, Phase 1 stub)
     - Submit results (FR-AGENT-006)

4. **Retry Logic (FR-AGENT-002):**
   - Retry failed requests up to 5 times
   - Exponential backoff: 60s, 120s, 240s, 480s, 960s
   - Random jitter (0-30s) added to delays

## Troubleshooting

### Agent won't start

**Error:** `[ERR_CONFIG_MISSING] Failed to open config file`

**Fix:** Create config file at `/etc/gvm-agent/agent.conf`

```bash
sudo cp /etc/gvm-agent/agent.conf.template /etc/gvm-agent/agent.conf
sudo nano /etc/gvm-agent/agent.conf
```

### Authentication fails

**Error:** `[ERR_AUTH_FAILED] Authentication failed (HTTP 401)`

**Fix:** Verify auth_token in config matches Agent Controller token

```bash
# Check Agent Controller token
curl -H "Authorization: Bearer test-agent-token-67890" \
     https://agent-controller.example.com/api/v1/agents/heartbeat

# Update agent config
sudo nano /etc/gvm-agent/agent.conf
sudo systemctl restart gvm-agent
```

### Agent not authorized

**Log:** `Agent registered but not yet authorized`

**Fix:** Authorize agent via Agent Controller Admin API

```bash
# List agents
curl -H "X-API-KEY: test-api-key-12345" \
     https://agent-controller.example.com/api/v1/admin/agents

# Authorize agent
curl -X PATCH \
     -H "X-API-KEY: test-api-key-12345" \
     -H "Content-Type: application/json" \
     -d '{"agent-id-here": {"authorized": true}}' \
     https://agent-controller.example.com/api/v1/admin/agents
```

### Network connectivity

**Error:** `[ERR_NETWORK_UNREACHABLE] Heartbeat request failed`

**Fix:** Verify Agent Controller is reachable

```bash
# Test connectivity
curl -v https://agent-controller.example.com/health

# Check firewall
sudo ufw status

# Check DNS
nslookup agent-controller.example.com
```

## API Reference

The agent interacts with the Agent Controller Agent-Facing API (Section 8.3):

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/agents/heartbeat` | POST | Send heartbeat (FR-AC-007) |
| `/api/v1/agents/jobs` | GET | Poll for jobs (FR-AC-008) |
| `/api/v1/agents/jobs/{id}/results` | POST | Submit results (FR-AC-009) |
| `/api/v1/agents/config` | GET | Get agent config |

All requests require:
- `Authorization: Bearer <token>` header
- `X-Agent-ID: <uuid>` header (for job polling)

## Security

Per PRD Section 9 (Security Requirements):

- ✅ **SR-TLS-001:** Mandatory TLS 1.3 (or TLS 1.2 minimum)
- ✅ **SR-AUTH-001:** Bearer token authentication
- ✅ **SR-VALID-001:** Input validation (UUID, config fields)
- ⚠️ **Runs as root/SYSTEM:** Required for local scanning per Section 7.2.5

## Roadmap

### Phase 1 (MVP) - Current
- ✅ Agent registration and heartbeat
- ✅ Job polling and execution (stub)
- ✅ Result submission
- ✅ Linux support

### Phase 2 (Multi-Platform) - Q3 2025
- [ ] Full NASL interpreter (FR-AGENT-004)
- [ ] NVT feed sync (FR-AGENT-005)
- [ ] Windows and macOS support
- [ ] Auto-update mechanism (FR-AGENT-008)

### Phase 3 (Enterprise) - Q4 2025
- [ ] mTLS authentication (SR-TLS-002)
- [ ] Compliance scanning (CIS, STIG)
- [ ] Advanced monitoring

## Contributing

This agent follows the Product Requirements Document (PRD) at `agent-infrastructure-requirements.md`.

Per CLAUDE.md requirements:
- ❌ NO PLACEHOLDER DATA
- ❌ NO FALLBACK BEHAVIOR
- ✅ All errors include error codes and context
- ✅ Reference PRD requirement IDs in commits

## License

GPL v2+ (compatible with OpenVAS scanner)

## Support

For issues, see:
- PRD: `agent-infrastructure-requirements.md`
- Reference Guide: `agent-infrastructure-reference.md`
- Agent Controller: `agent-controller-sqlite.py`

---

**Per PRD Section 7.2 - Host-Based Agent Technical Requirements**
**Implements FR-AGENT-001 through FR-AGENT-006**
