/**
 * GVM Agent - Configuration Parser Header
 * Per PRD Section 7.2.4 - Configuration File Format (TOML/INI)
 *
 * Configuration location per Section 7.2.4:
 * - Linux: /etc/gvm-agent/agent.conf
 * - Windows: C:\Program Files\GVM Agent\agent.conf
 * - macOS: /Library/Application Support/GVM Agent/agent.conf
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "agent.h"

/**
 * Load configuration from file
 * Per Section 7.2.4: TOML or INI format
 * Per CLAUDE.md: NO FALLBACK BEHAVIOR - return error if config missing
 *
 * @param config_path Path to agent.conf
 * @param config_out Loaded configuration (caller must free with config_free)
 * @return ERR_SUCCESS or error code
 */
int config_load(const char *config_path, agent_config_t **config_out);

/**
 * Free configuration
 *
 * @param config Configuration to free
 */
void config_free(agent_config_t *config);

/**
 * Validate configuration
 * Per Section 7.2.4: Ensure all required fields present
 *
 * @param config Configuration to validate
 * @return ERR_SUCCESS or ERR_CONFIG_INVALID with specific error
 */
int config_validate(const agent_config_t *config);

/**
 * Get default config path for platform
 * Per Section 7.2.4
 *
 * @return Default config path (static string, do not free)
 */
const char* config_get_default_path(void);

#endif /* CONFIG_H */
