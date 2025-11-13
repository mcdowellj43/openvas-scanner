/**
 * GVM Agent - Main Entry Point
 * Per PRD Section 7.2 - Host-Based Agent
 *
 * Implements agent-based vulnerability scanning per:
 * - FR-AGENT-001: Agent Registration
 * - FR-AGENT-002: Periodic Heartbeat
 * - FR-AGENT-003: Job Polling
 * - FR-AGENT-004: Local Vulnerability Scanning (stub in Phase 1)
 * - FR-AGENT-006: Result Submission
 */

#include "agent.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

static agent_context_t *g_agent_ctx = NULL;

void signal_handler(int signum) {
    utils_log_info("Received signal %d, shutting down gracefully...", signum);

    if (g_agent_ctx != NULL) {
        agent_cleanup(g_agent_ctx);
        g_agent_ctx = NULL;
    }

    exit(0);
}

void print_usage(const char *program_name) {
    printf("GVM Agent v%s\n", AGENT_VERSION);
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\n");
    printf("Options:\n");
    printf("  -c, --config PATH    Path to configuration file\n");
    printf("                       (default: /etc/gvm-agent/agent.conf)\n");
    printf("  -h, --help           Display this help message\n");
    printf("  -v, --version        Display version information\n");
    printf("\n");
    printf("Per CLAUDE.md requirements:\n");
    printf("  - NO PLACEHOLDER DATA\n");
    printf("  - NO FALLBACK BEHAVIOR\n");
    printf("  - All errors include specific error codes and context\n");
    printf("\n");
}

void print_version(void) {
    printf("GVM Agent v%s\n", AGENT_VERSION);
    printf("Protocol Version: %s\n", AGENT_PROTOCOL_VERSION);
    printf("\n");
    printf("Per PRD Section 7.2 - Host-Based Agent\n");
    printf("Implements:\n");
    printf("  - FR-AGENT-001: Agent Registration\n");
    printf("  - FR-AGENT-002: Periodic Heartbeat\n");
    printf("  - FR-AGENT-003: Job Polling\n");
    printf("  - FR-AGENT-004: Local Vulnerability Scanning (Phase 1 stub)\n");
    printf("  - FR-AGENT-006: Result Submission\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    const char *config_path = NULL;

    /* Parse command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 < argc) {
                config_path = argv[i + 1];
                i++;
            } else {
                fprintf(stderr, "Error: --config requires a path argument\n");
                print_usage(argv[0]);
                return 1;
            }
        } else {
            fprintf(stderr, "Error: Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Register signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize agent per FR-AGENT-001 */
    g_agent_ctx = agent_init(config_path);
    if (g_agent_ctx == NULL) {
        fprintf(stderr, "Failed to initialize agent\n");
        fprintf(stderr, "Check logs for detailed error information\n");
        return 1;
    }

    /* Run agent main loop per FR-AGENT-002 and FR-AGENT-003 */
    int exit_code = agent_run(g_agent_ctx);

    /* Cleanup */
    agent_cleanup(g_agent_ctx);

    return exit_code;
}
