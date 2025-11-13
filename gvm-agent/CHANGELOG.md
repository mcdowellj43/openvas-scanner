# Changelog

All notable changes to GVM Agent will be documented in this file.

## [2.0.0] - Phase 2 - 2025-11-13

### Added

- **FR-AGENT-005**: NVT Feed Synchronization
  - rsync-based feed synchronization from Greenbone community feed
  - GPG signature verification for feed integrity
  - SQLite3-based NVT cache database for fast OID lookups
  - Automatic feed index rebuilding after sync
  - Feed sync scheduling (configurable, default: daily at 2 AM)

- **FR-AGENT-004**: Full Local Vulnerability Scanning
  - NASL script executor with openvas-nasl integration
  - Built-in basic security checks (fallback when openvas-nasl not available)
  - Real vulnerability scan results with proper formatting
  - Support for scan preferences (max_checks, max_hosts, timeout)
  - Multi-VT scan execution with rate limiting

- **FR-AGENT-008**: Auto-Update Mechanism
  - Check for agent updates via Agent Controller API
  - Download new binary with checksum verification (SHA256)
  - Self-update and automatic restart
  - Permission checks before update

- **Infrastructure:**
  - SQLite3 NVT cache database with OID index
  - Enhanced job processor with real scan execution
  - NASL file parser for extracting metadata
  - Improved error handling with Phase 2 error codes

### Changed

- Version bumped from 1.0.0 to 2.0.0
- job_processor.c: Now executes real scans instead of stubs
- CMakeLists.txt: Added SQLite3 dependency
- Package dependencies: Added libsqlite3-0, rsync, uuid-runtime

### Dependencies

**New Runtime Dependencies:**
- SQLite3 >= 3.7
- rsync (for NVT feed sync)
- uuid-runtime (for UUID generation)
- gnupg (optional, for GPG verification)
- openvas-nasl (optional, for full NASL execution)

**New Build Dependencies:**
- libsqlite3-dev
- uuid-dev

## [1.0.0] - Phase 1 MVP - 2025-11-13

### Added

- **FR-AGENT-001**: Agent Registration
  - Auto-registration on first heartbeat
  - UUID generation if not configured
  - System information collection (OS, arch, IPs)

- **FR-AGENT-002**: Periodic Heartbeat
  - Heartbeat every 600 seconds (configurable)
  - Exponential backoff retry (5 attempts: 60s, 120s, 240s, 480s, 960s)
  - Random jitter (0-30s) for retry delays

- **FR-AGENT-003**: Job Polling
  - Poll GET /api/v1/agents/jobs for scan jobs
  - X-Agent-ID header for agent identification

- **FR-AGENT-006**: Result Submission
  - POST /api/v1/agents/jobs/{id}/results
  - JSON-formatted scan results per PRD Section 6.1

- **Security:**
  - SR-TLS-001: Mandatory TLS via libcurl
  - SR-AUTH-001: Bearer token authentication
  - SR-VALID-001: Input validation (UUID, config fields)

- **Configuration:**
  - INI-style config file format
  - Required fields: controller.url, auth_token
  - NO FALLBACK BEHAVIOR per CLAUDE.md

- **Build System:**
  - CMake 3.10+ with CPack
  - Linux packages: .deb and .rpm
  - Windows cross-compile ready
  - Makefile shortcuts

### Infrastructure

- Language: C (C11 standard)
- HTTP Client: libcurl
- Platform Support: Linux, Windows
- Build Tools: CMake, CPack

---

## Version Format

This project uses [Semantic Versioning](https://semver.org/):
- **Major**: Breaking changes or new phase releases
- **Minor**: New features within a phase
- **Patch**: Bug fixes and minor improvements

## Reference

- PRD: agent-infrastructure-requirements.md
- Quick Reference: agent-infrastructure-reference.md
- Agent Controller: agent-controller-sqlite.py
