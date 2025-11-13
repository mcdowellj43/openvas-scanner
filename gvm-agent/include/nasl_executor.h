/**
 * GVM Agent - NASL Executor Header
 * Per PRD Section 6.2 (FR-AGENT-004) - Local Vulnerability Scanning
 *
 * Phase 2 Implementation:
 * - Execute NASL scripts against localhost
 * - Collect vulnerability findings
 * - Return results in OpenVAS format
 *
 * Note: Full NASL interpreter would require forking OpenVAS scanner.
 * This implementation uses a simplified executor that shells out to
 * openvas-nasl if available, or runs basic checks.
 */

#ifndef NASL_EXECUTOR_H
#define NASL_EXECUTOR_H

#include "agent.h"
#include "nvt_feed.h"
#include <stdbool.h>

/* Scan result structure per PRD Section 6.1 FR-AC-009 */
typedef struct {
    char *nvt_oid;
    char *nvt_name;
    float severity;
    char *cvss_base_vector;
    char *host;
    char *port;
    char *threat;
    char *description;
    int qod;  /* Quality of Detection: 0-100 */
} scan_result_t;

/* Scan result list */
typedef struct {
    scan_result_t *results;
    int result_count;
} scan_result_list_t;

/* Scan preferences per PRD Section 6.1 */
typedef struct {
    int max_checks;        /* Max concurrent checks (default: 4) */
    int max_hosts;         /* Max hosts to scan (default: 20) */
    int timeout_minutes;   /* Scan timeout (default: 60) */
} scan_preferences_t;

/**
 * Initialize NASL executor
 * Checks for openvas-nasl binary or uses built-in checks
 *
 * @return ERR_SUCCESS or error code
 */
int nasl_executor_init(void);

/**
 * Execute single NASL script
 * Per FR-AGENT-004: Execute VT by OID against localhost
 *
 * @param nvt NVT record to execute
 * @param target Target host (default: "localhost")
 * @param port_list Port list (e.g., "1-65535")
 * @param preferences Scan preferences
 * @param results_out Scan results (caller must free with scan_result_list_free)
 * @return ERR_SUCCESS or error code
 */
int nasl_executor_run_script(
    const nvt_record_t *nvt,
    const char *target,
    const char *port_list,
    const scan_preferences_t *preferences,
    scan_result_list_t **results_out
);

/**
 * Execute multiple NASL scripts (full scan)
 * Per FR-AGENT-004: Execute full vulnerability scan
 *
 * @param oids Array of NVT OIDs to execute
 * @param oid_count Number of OIDs
 * @param target Target host (default: "localhost")
 * @param port_list Port list
 * @param preferences Scan preferences
 * @param results_out Aggregated scan results (caller must free)
 * @return ERR_SUCCESS or error code
 */
int nasl_executor_run_scan(
    const char **oids,
    int oid_count,
    const char *target,
    const char *port_list,
    const scan_preferences_t *preferences,
    scan_result_list_t **results_out
);

/**
 * Free scan result list
 *
 * @param results Results to free
 */
void scan_result_list_free(scan_result_list_t *results);

/**
 * Free single scan result
 *
 * @param result Result to free
 */
void scan_result_free(scan_result_t *result);

/**
 * Check if openvas-nasl is available
 * If not, use built-in basic checks
 *
 * @return true if openvas-nasl found
 */
bool nasl_executor_has_openvas_nasl(void);

/**
 * Run built-in basic security checks (fallback)
 * Used when openvas-nasl is not available
 *
 * Checks:
 * - Open ports scan
 * - SSH version detection
 * - HTTP server detection
 * - Common service detection
 *
 * @param target Target host
 * @param results_out Basic scan results
 * @return ERR_SUCCESS or error code
 */
int nasl_executor_run_basic_checks(const char *target, scan_result_list_t **results_out);

#endif /* NASL_EXECUTOR_H */
