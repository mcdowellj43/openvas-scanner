/**
 * GVM Agent - Job Processor Header
 * Per PRD Section 6.2 (FR-AGENT-003, FR-AGENT-004, FR-AGENT-006)
 *
 * Implements:
 * - FR-AGENT-003: Job Polling
 * - FR-AGENT-004: Local Vulnerability Scanning (stub in Phase 1)
 * - FR-AGENT-006: Result Submission
 */

#ifndef JOB_PROCESSOR_H
#define JOB_PROCESSOR_H

#include "agent.h"
#include <stdbool.h>

/* Job structure per PRD Section 6.1 FR-AC-008 */
typedef struct {
    char *job_id;
    char *scan_id;
    char *job_type;
    char *priority;
    char *created_at;
    char *config_json;  /* Full config as JSON string */
} job_t;

/* Job list structure */
typedef struct {
    job_t *jobs;
    int job_count;
} job_list_t;

/**
 * Poll for scan jobs
 * Per FR-AGENT-003: Job Polling
 * Per FR-AC-008: GET /api/v1/agents/jobs
 *
 * Request headers:
 * - Authorization: Bearer <agent-token>
 * - X-Agent-ID: <agent-uuid>
 *
 * Response:
 * {
 *   "jobs": [
 *     {
 *       "job_id": "job-12345",
 *       "scan_id": "550e8400-...",
 *       "job_type": "vulnerability_scan",
 *       "priority": "normal",
 *       "created_at": "2025-01-15T10:25:00Z",
 *       "config": { ... }
 *     }
 *   ]
 * }
 *
 * @param ctx Agent context
 * @param jobs_out Job list (caller must free with job_list_free)
 * @return ERR_SUCCESS or error code
 */
int job_poll(agent_context_t *ctx, job_list_t **jobs_out);

/**
 * Execute a scan job
 * Per FR-AGENT-004: Local Vulnerability Scanning
 *
 * Phase 1 Implementation: Stub - returns mock results
 * Full Implementation (Phase 2): Execute NASL scripts per Section 6.2
 *
 * @param ctx Agent context
 * @param job Job to execute
 * @param results_json_out JSON results string (caller must free)
 * @return ERR_SUCCESS or error code
 */
int job_execute(agent_context_t *ctx, job_t *job, char **results_json_out);

/**
 * Submit scan results
 * Per FR-AGENT-006: Result Submission
 * Per FR-AC-009: POST /api/v1/agents/jobs/{job_id}/results
 *
 * Request body per Section 6.1:
 * {
 *   "job_id": "job-12345",
 *   "scan_id": "550e8400-...",
 *   "agent_id": "550e8400-...",
 *   "status": "completed",
 *   "started_at": "2025-01-15T10:30:00Z",
 *   "completed_at": "2025-01-15T10:45:00Z",
 *   "results": [ ... ]
 * }
 *
 * Response: HTTP 202 Accepted
 * {
 *   "status": "accepted",
 *   "results_received": 1
 * }
 *
 * @param ctx Agent context
 * @param job_id Job ID
 * @param scan_id Scan ID
 * @param results_json JSON results from job_execute
 * @return ERR_SUCCESS or error code
 */
int job_submit_results(agent_context_t *ctx, const char *job_id, const char *scan_id, const char *results_json);

/**
 * Free job list
 *
 * @param jobs Job list to free
 */
void job_list_free(job_list_t *jobs);

/**
 * Free single job
 *
 * @param job Job to free
 */
void job_free(job_t *job);

#endif /* JOB_PROCESSOR_H */
