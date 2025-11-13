/**
 * GVM Agent - Heartbeat Module Header
 * Per PRD Section 6.2 (FR-AGENT-002) - Periodic Heartbeat
 *
 * Implements:
 * - Send heartbeat every N seconds (default: 600)
 * - Retry with exponential backoff on failure
 * - Update agent status (authorized flag)
 */

#ifndef HEARTBEAT_H
#define HEARTBEAT_H

#include "agent.h"
#include <stdbool.h>

/* Heartbeat response per PRD Section 6.1 FR-AC-007 */
typedef struct {
    bool accepted;
    bool config_updated;
    int next_heartbeat_in_seconds;
    bool authorized;
} heartbeat_response_t;

/**
 * Send heartbeat to Agent Controller
 * Per FR-AGENT-002: Periodic Heartbeat
 * Per FR-AC-007: POST /api/v1/agents/heartbeat
 *
 * Request body per Section 6.1:
 * {
 *   "agent_id": "550e8400-...",
 *   "hostname": "server1.example.com",
 *   "connection_status": "active",
 *   "ip_addresses": ["192.168.1.100", "10.0.0.50"],
 *   "agent_version": "1.0.0",
 *   "operating_system": "Ubuntu 22.04 LTS",
 *   "architecture": "amd64"
 * }
 *
 * Response:
 * {
 *   "status": "accepted",
 *   "config_updated": false,
 *   "next_heartbeat_in_seconds": 600,
 *   "authorized": true
 * }
 *
 * @param ctx Agent context
 * @param response_out Heartbeat response (caller must free)
 * @return ERR_SUCCESS or error code
 */
int heartbeat_send(agent_context_t *ctx, heartbeat_response_t **response_out);

/**
 * Free heartbeat response
 *
 * @param response Response to free
 */
void heartbeat_response_free(heartbeat_response_t *response);

/**
 * Perform heartbeat with retry logic
 * Per FR-AGENT-002: Retry with exponential backoff
 *
 * Retry Logic per Section 6.2:
 * Attempt 1: Send heartbeat
 *   └─ Failed → Wait 60s + random(0-30s)
 * Attempt 2: Send heartbeat
 *   └─ Failed → Wait 120s + random(0-30s)
 * Attempt 3: Send heartbeat
 *   └─ Failed → Wait 240s + random(0-30s)
 * Attempt 4: Send heartbeat
 *   └─ Failed → Wait 480s + random(0-30s)
 * Attempt 5: Send heartbeat
 *   └─ Failed → Give up, wait for next interval
 *
 * @param ctx Agent context
 * @param response_out Heartbeat response (caller must free)
 * @return ERR_SUCCESS or error code
 */
int heartbeat_send_with_retry(agent_context_t *ctx, heartbeat_response_t **response_out);

#endif /* HEARTBEAT_H */
