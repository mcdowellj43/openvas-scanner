Agent-Based Scanning System - Product Requirements
Primary Requirements Document
IMPORTANT: All implementation work must reference agent-infrastructure-requirements.md as the authoritative source for:

System architecture (3-layer: gvmd → Agent Controller → Agents)
Functional requirements (29 detailed FR-* requirements)
Technical requirements (database schema, API specs, technology stack)
API specifications (Scanner API, Admin API, Agent-Facing API)
Security requirements (authentication, TLS, encryption, audit)
Performance requirements (scalability, latency targets)
Implementation phases (MVP → Multi-Platform → Enterprise)
Navigation Guide
START HERE: Use agent-controller-reference.md to quickly navigate the full PRD

Contains role-based quick-start paths (Engineer, PM, Security, Stakeholder)
Section lookup table for common needs
Cross-references between requirements and implementation details
Critical Implementation Rules
NO PLACEHOLDER DATA:

NEVER use placeholder values like "TODO", "FIXME", "placeholder", "example.com", "changeme"
NEVER use fake UUIDs like "00000000-0000-0000-0000-000000000000"
NEVER use dummy credentials like "password123", "admin/admin"
NEVER use hardcoded test IPs like "192.168.1.1", "10.0.0.1"
NO FALLBACK BEHAVIOR:

DO NOT silently fall back to default values when configuration is missing
DO NOT use "best guess" logic when requirements are ambiguous
DO NOT implement features not explicitly defined in the PRD
ERROR HANDLING: When encountering issues, return specific, trackable errors that include:

Error Code - Unique identifier (e.g., ERR_AGENT_AUTH_001)
Context - What operation was being attempted
Root Cause - Why it failed (be specific)
Location - File, function, line number if applicable
Fix Suggestion - What needs to be configured/corrected
Example of CORRECT error:

ERROR [ERR_AGENT_CONTROLLER_DB_001]: Failed to connect to PostgreSQL database
Context: Agent Controller startup, initializing database connection
Root Cause: Connection refused to postgresql://localhost:5432/agent_controller
  - SQLSTATE: 08006
  - Postgres error: "could not connect to server: Connection refused"
Location: internal/database/connection.go:45 in NewDBConnection()
Fix: Verify PostgreSQL is running and accessible:
  1. Check service: systemctl status postgresql
  2. Verify host/port in config: /etc/agent-controller/config.yaml
  3. Check firewall: sudo ufw status
  4. Test connection: psql -h localhost -p 5432 -U agent_controller -d agent_controller
Example of INCORRECT error (too vague):

ERROR: Database connection failed
Requirement Reference Format
When implementing features, always reference the specific requirement:

Format: FR-AC-001 (Functional Requirement - Agent Controller - Number)
Include in commit messages: "Implement FR-AC-001: Scanner API create scan endpoint"
Include in code comments: // Per FR-AC-001: Validate agent UUIDs before queuing jobs
Include in error messages: "Validation failed per FR-AC-001: agent_id must be valid UUID"
Architecture Validation
Before implementing any component, verify against:

Section 5 (System Architecture) - Ensure component fits in 3-layer design
Section 8 (API Specifications) - Verify endpoints, methods, payloads match exactly
Section 7 (Technical Requirements) - Use specified tech stack (Go, PostgreSQL, C, etc.)
Section 9 (Security Requirements) - Implement all security controls (TLS, auth, validation)
Code Quality Standards
All database schemas must match Section 7.1.2 exactly
All API responses must match Section 8 JSON formats exactly
All configuration files must match Section 7.2.4 format exactly
All error responses must use Section 8.4 standard format
When in Doubt
If requirements are unclear or conflicting:

DO NOT GUESS - Return specific error explaining the ambiguity
Reference the specific section number where conflict exists
List the conflicting requirements or missing information
Suggest which stakeholder should clarify (Engineer/PM/Security)
Example:

AMBIGUITY DETECTED [AMB_AGENT_001]: Agent authentication method unclear
Conflict:
  - Section 8.3 states "Bearer token OR mTLS"
  - Section 9 (SR-AUTH-001) recommends "JWT for MVP, mTLS for enterprise"
  - Open Question Q8 lists both as options without final decision

Missing Information:
  - Which authentication method should be implemented for Phase 1 MVP?
  - Should both be supported simultaneously?
  - Is there a migration path from JWT to mTLS?

Blocking: FR-AC-007 (Accept Heartbeats) implementation
Recommendation: Product Owner to clarify authentication approach for MVP
Reference: PRD Section 14 (Open Questions) - Q8
