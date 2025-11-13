/**
 * GVM Agent - Auto-Update Module Header
 * Per PRD Section 6.2 (FR-AGENT-008) - Auto-Update (Optional)
 *
 * Implements:
 * - Check for agent updates
 * - Download new binary
 * - Verify signature
 * - Replace binary and restart
 */

#ifndef AUTO_UPDATE_H
#define AUTO_UPDATE_H

#include "agent.h"
#include <stdbool.h>

/* Update info structure */
typedef struct {
    bool update_available;
    char *latest_version;
    char *download_url;
    char *checksum;        /* SHA256 checksum */
    char *release_notes;
} update_info_t;

/**
 * Check for agent updates
 * Per FR-AGENT-008: GET /api/v1/agents/updates
 *
 * Response per Section 6.2:
 * {
 *   "update_available": true,
 *   "latest_version": "1.1.0",
 *   "download_url": "https://controller.example.com/api/v1/agents/updates/1.1.0/download",
 *   "checksum": "sha256:abcd1234...",
 *   "release_notes": "Bug fixes and performance improvements"
 * }
 *
 * @param ctx Agent context
 * @param update_info_out Update information (caller must free)
 * @return ERR_SUCCESS or error code
 */
int auto_update_check(agent_context_t *ctx, update_info_t **update_info_out);

/**
 * Download agent update
 * Per FR-AGENT-008: Download new binary
 *
 * @param ctx Agent context
 * @param download_url Update download URL
 * @param output_path Path to save downloaded binary
 * @return ERR_SUCCESS or error code
 */
int auto_update_download(agent_context_t *ctx, const char *download_url, const char *output_path);

/**
 * Verify update checksum
 * Per FR-AGENT-008: Verify binary signature
 *
 * @param file_path Path to downloaded binary
 * @param expected_checksum Expected SHA256 checksum
 * @return true if checksum matches
 */
bool auto_update_verify_checksum(const char *file_path, const char *expected_checksum);

/**
 * Install update and restart agent
 * Per FR-AGENT-008: Replace binary and restart
 *
 * Update Flow per Section 6.2:
 * 1. Download new binary to temp location
 * 2. Verify checksum
 * 3. Replace current binary
 * 4. Restart service/process
 *
 * @param ctx Agent context
 * @param new_binary_path Path to new binary
 * @return ERR_SUCCESS or error code (does not return if successful)
 */
int auto_update_install_and_restart(agent_context_t *ctx, const char *new_binary_path);

/**
 * Free update info
 *
 * @param info Update info to free
 */
void update_info_free(update_info_t *info);

/**
 * Get platform-specific binary path
 * Returns current executable path
 *
 * @param path_out Executable path (caller must free)
 * @return ERR_SUCCESS or error code
 */
int auto_update_get_binary_path(char **path_out);

/**
 * Check if agent has update permission
 * Verifies agent can write to its own binary location
 *
 * @return true if agent can self-update
 */
bool auto_update_has_permission(void);

#endif /* AUTO_UPDATE_H */
