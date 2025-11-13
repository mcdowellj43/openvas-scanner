/**
 * GVM Agent - Configuration Parser Implementation
 * Per PRD Section 7.2.4 - Configuration File Format (INI-style)
 */

#include "config.h"
#include "utils.h"
#include "agent.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 1024

const char* config_get_default_path(void) {
#ifdef _WIN32
    return "C:\\Program Files\\GVM Agent\\agent.conf";
#elif __APPLE__
    return "/Library/Application Support/GVM Agent/agent.conf";
#else
    return "/etc/gvm-agent/agent.conf";
#endif
}

static char* trim_whitespace(char *str) {
    char *end;

    /* Trim leading space */
    while (*str == ' ' || *str == '\t') str++;

    if (*str == 0) {
        return str;
    }

    /* Trim trailing space */
    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) end--;

    *(end + 1) = '\0';

    return str;
}

int config_load(const char *config_path, agent_config_t **config_out) {
    if (config_path == NULL || config_out == NULL) {
        utils_log_error("[ERR_CONFIG_MISSING] Config path is NULL");
        return ERR_CONFIG_MISSING;
    }

    FILE *file = fopen(config_path, "r");
    if (file == NULL) {
        utils_log_error("[ERR_CONFIG_MISSING] Failed to open config file: %s", config_path);
        utils_log_error("Context: Loading agent configuration");
        utils_log_error("Root Cause: Config file does not exist or is not readable");
        utils_log_error("Location: config.c:config_load()");
        utils_log_error("Fix: Create config file at %s", config_path);
        return ERR_CONFIG_MISSING;
    }

    agent_config_t *config = calloc(1, sizeof(agent_config_t));
    if (config == NULL) {
        fclose(file);
        return ERR_CONFIG_INVALID;
    }

    /* Set defaults per Section 7.2.4 */
    config->heartbeat_interval_seconds = 600;
    config->retry_attempts = 5;
    config->retry_delay_seconds = 60;
    config->max_jitter_seconds = 30;
    config->log_level = utils_strdup("info");

    char line[MAX_LINE_LENGTH];
    char current_section[64] = "";

    while (fgets(line, sizeof(line), file)) {
        char *trimmed = trim_whitespace(line);

        /* Skip empty lines and comments */
        if (trimmed[0] == '\0' || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }

        /* Check for section header */
        if (trimmed[0] == '[') {
            char *section_end = strchr(trimmed, ']');
            if (section_end != NULL) {
                *section_end = '\0';
                strncpy(current_section, trimmed + 1, sizeof(current_section) - 1);
                continue;
            }
        }

        /* Parse key=value */
        char *equals = strchr(trimmed, '=');
        if (equals == NULL) {
            continue;
        }

        *equals = '\0';
        char *key = trim_whitespace(trimmed);
        char *value = trim_whitespace(equals + 1);

        /* Remove quotes from value */
        if (value[0] == '"') {
            value++;
            char *end_quote = strchr(value, '"');
            if (end_quote != NULL) {
                *end_quote = '\0';
            }
        }

        /* Parse configuration values per Section 7.2.4 */
        if (strcmp(current_section, "agent") == 0) {
            if (strcmp(key, "agent_id") == 0) {
                config->agent_id = utils_strdup(value);
            } else if (strcmp(key, "hostname") == 0) {
                config->hostname = utils_strdup(value);
            }
        } else if (strcmp(current_section, "controller") == 0) {
            if (strcmp(key, "url") == 0) {
                config->controller_url = utils_strdup(value);
            } else if (strcmp(key, "auth_token") == 0) {
                config->auth_token = utils_strdup(value);
            }
        } else if (strcmp(current_section, "heartbeat") == 0) {
            if (strcmp(key, "interval_in_seconds") == 0) {
                config->heartbeat_interval_seconds = atoi(value);
            } else if (strcmp(key, "miss_until_inactive") == 0) {
                /* Not used in agent, only in controller */
            }
        } else if (strcmp(current_section, "retry") == 0) {
            if (strcmp(key, "attempts") == 0) {
                config->retry_attempts = atoi(value);
            } else if (strcmp(key, "delay_in_seconds") == 0) {
                config->retry_delay_seconds = atoi(value);
            } else if (strcmp(key, "max_jitter_in_seconds") == 0) {
                config->max_jitter_seconds = atoi(value);
            }
        } else if (strcmp(current_section, "logging") == 0) {
            if (strcmp(key, "level") == 0) {
                free(config->log_level);
                config->log_level = utils_strdup(value);
            }
        }
    }

    fclose(file);

    /* Validate configuration */
    int validate_result = config_validate(config);
    if (validate_result != ERR_SUCCESS) {
        config_free(config);
        return validate_result;
    }

    *config_out = config;
    utils_log_info("Configuration loaded from %s", config_path);
    return ERR_SUCCESS;
}

int config_validate(const agent_config_t *config) {
    if (config == NULL) {
        return ERR_CONFIG_INVALID;
    }

    /* Per CLAUDE.md: NO FALLBACK BEHAVIOR - require all critical fields */
    if (config->controller_url == NULL || strlen(config->controller_url) == 0) {
        utils_log_error("[ERR_CONFIG_INVALID] Missing required field: controller.url");
        utils_log_error("Context: Validating agent configuration");
        utils_log_error("Root Cause: controller_url is not set in config file");
        utils_log_error("Location: config.c:config_validate()");
        utils_log_error("Fix: Add 'url = https://controller.example.com' under [controller] section");
        return ERR_CONFIG_INVALID;
    }

    if (config->auth_token == NULL || strlen(config->auth_token) == 0) {
        utils_log_error("[ERR_CONFIG_INVALID] Missing required field: controller.auth_token");
        utils_log_error("Context: Validating agent configuration");
        utils_log_error("Root Cause: auth_token is not set in config file");
        utils_log_error("Location: config.c:config_validate()");
        utils_log_error("Fix: Add 'auth_token = <your-token>' under [controller] section");
        return ERR_CONFIG_INVALID;
    }

    if (config->heartbeat_interval_seconds < 60) {
        utils_log_error("[ERR_CONFIG_INVALID] Invalid heartbeat_interval_seconds: %d (must be >= 60)",
                       config->heartbeat_interval_seconds);
        return ERR_CONFIG_INVALID;
    }

    return ERR_SUCCESS;
}

void config_free(agent_config_t *config) {
    if (config == NULL) {
        return;
    }

    free(config->agent_id);
    free(config->hostname);
    free(config->controller_url);
    free(config->auth_token);
    free(config->log_level);
    free(config);
}
