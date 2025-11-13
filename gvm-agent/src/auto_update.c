/**
 * GVM Agent - Auto-Update Module Implementation
 * Per PRD Section 6.2 (FR-AGENT-008) - Auto-Update
 */

#include "auto_update.h"
#include "http_client.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/types.h>
#include <pwd.h>
#endif

int auto_update_check(agent_context_t *ctx, update_info_t **update_info_out) {
    if (ctx == NULL || update_info_out == NULL) {
        return ERR_INVALID_RESPONSE;
    }

    /* Build update check URL per FR-AGENT-008: GET /api/v1/agents/updates */
    char *update_url = NULL;
    if (!utils_build_url(ctx->config->controller_url, "/api/v1/agents/updates", &update_url)) {
        utils_log_error("[ERR_NETWORK_UNREACHABLE] Failed to build update URL");
        return ERR_NETWORK_UNREACHABLE;
    }

    utils_log_debug("Checking for updates at %s", update_url);

    /* Send HTTP GET */
    http_response_t *http_response = NULL;
    bool success = http_get(update_url, ctx->config->auth_token, &http_response);
    free(update_url);

    if (!success || http_response == NULL) {
        utils_log_error("[ERR_NETWORK_UNREACHABLE] Update check failed");
        if (http_response != NULL) {
            http_response_free(http_response);
        }
        return ERR_NETWORK_UNREACHABLE;
    }

    if (http_response->status_code != 200) {
        utils_log_error("[ERR_SERVER_ERROR] Update check failed with HTTP %d", http_response->status_code);
        http_response_free(http_response);
        return ERR_SERVER_ERROR;
    }

    /* Parse response per Section 6.2 */
    update_info_t *info = calloc(1, sizeof(update_info_t));
    if (info == NULL) {
        http_response_free(http_response);
        return ERR_INVALID_RESPONSE;
    }

    /* Parse JSON fields */
    http_parse_json_bool(http_response->body, "update_available", &info->update_available);
    http_parse_json_string(http_response->body, "latest_version", &info->latest_version);
    http_parse_json_string(http_response->body, "download_url", &info->download_url);
    http_parse_json_string(http_response->body, "checksum", &info->checksum);
    http_parse_json_string(http_response->body, "release_notes", &info->release_notes);

    if (info->update_available) {
        utils_log_info("Update available: v%s (current: v%s)",
                      info->latest_version ? info->latest_version : "unknown",
                      AGENT_VERSION);
    } else {
        utils_log_info("Agent is up to date (v%s)", AGENT_VERSION);
    }

    http_response_free(http_response);
    *update_info_out = info;
    return ERR_SUCCESS;
}

int auto_update_download(agent_context_t *ctx, const char *download_url, const char *output_path) {
    if (ctx == NULL || download_url == NULL || output_path == NULL) {
        return ERR_INVALID_RESPONSE;
    }

    utils_log_info("Downloading update from %s", download_url);

    /* Send HTTP GET to download binary */
    http_response_t *http_response = NULL;
    bool success = http_get(download_url, ctx->config->auth_token, &http_response);

    if (!success || http_response == NULL) {
        utils_log_error("[ERR_NETWORK_UNREACHABLE] Update download failed");
        if (http_response != NULL) {
            http_response_free(http_response);
        }
        return ERR_NETWORK_UNREACHABLE;
    }

    if (http_response->status_code != 200) {
        utils_log_error("[ERR_SERVER_ERROR] Update download failed with HTTP %d", http_response->status_code);
        http_response_free(http_response);
        return ERR_SERVER_ERROR;
    }

    /* Write binary to file */
    FILE *fp = fopen(output_path, "wb");
    if (fp == NULL) {
        utils_log_error("[ERR_DISK_ERROR] Failed to open output file: %s", output_path);
        http_response_free(http_response);
        return ERR_CONFIG_INVALID;
    }

    fwrite(http_response->body, 1, http_response->body_size, fp);
    fclose(fp);

    /* Make executable on Unix */
#ifndef _WIN32
    chmod(output_path, 0755);
#endif

    utils_log_info("Update downloaded successfully: %s (%zu bytes)", output_path, http_response->body_size);

    http_response_free(http_response);
    return ERR_SUCCESS;
}

bool auto_update_verify_checksum(const char *file_path, const char *expected_checksum) {
    if (file_path == NULL || expected_checksum == NULL) {
        return false;
    }

    /* Extract algorithm and hash from expected_checksum (format: "sha256:abcd1234...") */
    if (strncmp(expected_checksum, "sha256:", 7) != 0) {
        utils_log_error("Unsupported checksum format: %s", expected_checksum);
        return false;
    }

    const char *expected_hash = expected_checksum + 7;

    /* Calculate SHA256 using system command */
    char sha_cmd[1024];
#ifdef _WIN32
    snprintf(sha_cmd, sizeof(sha_cmd), "certutil -hashfile \"%s\" SHA256", file_path);
#else
    snprintf(sha_cmd, sizeof(sha_cmd), "sha256sum \"%s\"", file_path);
#endif

    FILE *fp = popen(sha_cmd, "r");
    if (fp == NULL) {
        utils_log_error("Failed to calculate checksum");
        return false;
    }

    char line[256];
    char actual_hash[65] = "";

    while (fgets(line, sizeof(line), fp) != NULL) {
#ifdef _WIN32
        /* certutil output: skip first line, hash is on second line */
        if (strlen(line) >= 64 && strstr(line, " ") == NULL) {
            strncpy(actual_hash, line, 64);
            actual_hash[64] = '\0';
        }
#else
        /* sha256sum output: "hash  filename" */
        sscanf(line, "%64s", actual_hash);
#endif
    }

    pclose(fp);

    /* Compare checksums (case-insensitive) */
    if (strcasecmp(actual_hash, expected_hash) == 0) {
        utils_log_info("Checksum verified successfully");
        return true;
    }

    utils_log_error("Checksum mismatch!");
    utils_log_error("  Expected: %s", expected_hash);
    utils_log_error("  Actual:   %s", actual_hash);
    return false;
}

int auto_update_get_binary_path(char **path_out) {
    if (path_out == NULL) {
        return ERR_INVALID_RESPONSE;
    }

#ifdef _WIN32
    char path[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (len == 0) {
        return ERR_INVALID_RESPONSE;
    }
    *path_out = utils_strdup(path);
#else
    char path[1024];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len == -1) {
        /* Fallback for non-Linux systems */
        *path_out = utils_strdup("/usr/bin/gvm-agent");
    } else {
        path[len] = '\0';
        *path_out = utils_strdup(path);
    }
#endif

    return ERR_SUCCESS;
}

bool auto_update_has_permission(void) {
    /* Check if agent can write to its own binary */
    char *binary_path = NULL;
    if (auto_update_get_binary_path(&binary_path) != ERR_SUCCESS) {
        return false;
    }

    /* Check write permission */
    bool has_permission = (access(binary_path, W_OK) == 0);
    free(binary_path);

    return has_permission;
}

int auto_update_install_and_restart(agent_context_t *ctx, const char *new_binary_path) {
    if (ctx == NULL || new_binary_path == NULL) {
        return ERR_INVALID_RESPONSE;
    }

    /* Get current binary path */
    char *current_binary = NULL;
    if (auto_update_get_binary_path(&current_binary) != ERR_SUCCESS) {
        utils_log_error("[ERR_UPDATE] Failed to get current binary path");
        return ERR_INVALID_RESPONSE;
    }

    utils_log_info("Installing update...");
    utils_log_info("  Current binary: %s", current_binary);
    utils_log_info("  New binary: %s", new_binary_path);

    /* Backup current binary */
    char backup_path[1024];
    snprintf(backup_path, sizeof(backup_path), "%s.backup", current_binary);

    if (rename(current_binary, backup_path) != 0) {
        utils_log_error("[ERR_UPDATE] Failed to backup current binary");
        free(current_binary);
        return ERR_CONFIG_INVALID;
    }

    /* Copy new binary to current location */
    if (rename(new_binary_path, current_binary) != 0) {
        utils_log_error("[ERR_UPDATE] Failed to install new binary");
        /* Restore backup */
        rename(backup_path, current_binary);
        free(current_binary);
        return ERR_CONFIG_INVALID;
    }

    utils_log_info("Update installed successfully");
    utils_log_info("Restarting agent...");

    /* Restart agent */
#ifdef _WIN32
    /* Windows: Restart service */
    system("net stop GVMAgent && net start GVMAgent");
#else
    /* Linux: Restart via systemd or exec */
    if (system("systemctl is-active --quiet gvm-agent") == 0) {
        /* Running as systemd service */
        system("systemctl restart gvm-agent");
    } else {
        /* Running manually - exec new binary */
        char *args[] = { current_binary, NULL };
        execv(current_binary, args);
    }
#endif

    free(current_binary);

    /* Should not reach here if restart succeeded */
    return ERR_SUCCESS;
}

void update_info_free(update_info_t *info) {
    if (info == NULL) {
        return;
    }

    free(info->latest_version);
    free(info->download_url);
    free(info->checksum);
    free(info->release_notes);
    free(info);
}
