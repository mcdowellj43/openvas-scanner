/**
 * GVM Agent - Main Agent Header
 * Per PRD Section 7.2 - Host-Based Agent Technical Requirements
 *
 * Implements:
 * - FR-AGENT-001: Agent Registration
 * - FR-AGENT-002: Periodic Heartbeat
 * - FR-AGENT-003: Job Polling
 *
 * IMPORTANT (per CLAUDE.md):
 * - NO PLACEHOLDER DATA
 * - NO FALLBACK BEHAVIOR
 * - Return specific, trackable errors
 */

#ifndef AGENT_H
#define AGENT_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Version information */
#define AGENT_VERSION "1.0.0"
#define AGENT_PROTOCOL_VERSION "1"

/* Error codes per CLAUDE.md requirements */
#define ERR_SUCCESS 0
#define ERR_CONFIG_MISSING 1001
#define ERR_CONFIG_INVALID 1002
#define ERR_NETWORK_UNREACHABLE 2001
#define ERR_AUTH_FAILED 2002
#define ERR_SERVER_ERROR 2003
#define ERR_INVALID_RESPONSE 2004
#define ERR_AGENT_UNAUTHORIZED 3001
#define ERR_JOB_EXECUTION_FAILED 3002

/* Agent state per Section 5.3 */
typedef enum {
    AGENT_STATE_INITIALIZING,
    AGENT_STATE_REGISTERING,
    AGENT_STATE_ACTIVE,
    AGENT_STATE_UNAUTHORIZED,
    AGENT_STATE_ERROR,
    AGENT_STATE_SHUTDOWN
} agent_state_t;

/* Agent configuration per Section 7.2.4 */
typedef struct {
    char *agent_id;                    /* UUID - generated or from config */
    char *hostname;                    /* System hostname */
    char *controller_url;              /* Agent Controller URL */
    char *auth_token;                  /* Bearer token for authentication */
    int heartbeat_interval_seconds;    /* Default: 600 per Section 7.2.4 */
    int retry_attempts;                /* Default: 5 per Section 7.2.4 */
    int retry_delay_seconds;           /* Default: 60 per Section 7.2.4 */
    int max_jitter_seconds;            /* Default: 30 per Section 7.2.4 */
    char *log_level;                   /* debug, info, warn, error */
} agent_config_t;

/* Agent context */
typedef struct {
    agent_config_t *config;
    agent_state_t state;
    bool authorized;
    time_t last_heartbeat;
    int retry_count;
    char *operating_system;
    char *architecture;
    char **ip_addresses;
    int ip_address_count;
} agent_context_t;

/**
 * Initialize agent
 * Per FR-AGENT-001: Agent Registration
 *
 * @param config_path Path to agent.conf
 * @return Agent context or NULL on error
 */
agent_context_t* agent_init(const char *config_path);

/**
 * Start agent main loop
 * Per FR-AGENT-002: Periodic Heartbeat
 * Per FR-AGENT-003: Job Polling
 *
 * @param ctx Agent context
 * @return Exit code (0 = success)
 */
int agent_run(agent_context_t *ctx);

/**
 * Cleanup agent resources
 *
 * @param ctx Agent context
 */
void agent_cleanup(agent_context_t *ctx);

/**
 * Get system information
 * Per FR-AGENT-001: Agent sends system info in heartbeat
 *
 * @param os_out Operating system string (caller must free)
 * @param arch_out Architecture string (caller must free)
 * @param ips_out Array of IP addresses (caller must free)
 * @param ip_count_out Number of IP addresses
 * @return ERR_SUCCESS or error code
 */
int agent_get_system_info(char **os_out, char **arch_out, char ***ips_out, int *ip_count_out);

/**
 * Generate or load agent UUID
 * Per FR-AGENT-001: Agent generates UUID on first run
 *
 * @param config_path Path to config file
 * @param uuid_out UUID string (caller must free)
 * @return ERR_SUCCESS or error code
 */
int agent_get_or_generate_uuid(const char *config_path, char **uuid_out);

#endif /* AGENT_H */
