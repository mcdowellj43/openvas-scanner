/**
 * GVM Agent - Heartbeat Module Implementation
 * Per PRD Section 6.2 (FR-AGENT-002) - Periodic Heartbeat
 */

#include "heartbeat.h"
#include "http_client.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int heartbeat_send(agent_context_t *ctx, heartbeat_response_t **response_out) {
    if (ctx == NULL || response_out == NULL) {
        return ERR_INVALID_RESPONSE;
    }

    /* Build heartbeat URL per FR-AC-007: POST /api/v1/agents/heartbeat */
    char *heartbeat_url = NULL;
    if (!utils_build_url(ctx->config->controller_url, "/api/v1/agents/heartbeat", &heartbeat_url)) {
        utils_log_error("[ERR_NETWORK_UNREACHABLE] Failed to build heartbeat URL");
        return ERR_NETWORK_UNREACHABLE;
    }

    /* Build JSON body per Section 6.1 FR-AC-007 */
    char json_body[4096];
    char ip_addresses_json[1024] = "[";

    /* Build IP addresses array */
    for (int i = 0; i < ctx->ip_address_count; i++) {
        if (i > 0) {
            strcat(ip_addresses_json, ", ");
        }
        char ip_json[64];
        snprintf(ip_json, sizeof(ip_json), "\"%s\"", ctx->ip_addresses[i]);
        strcat(ip_addresses_json, ip_json);
    }
    strcat(ip_addresses_json, "]");

    snprintf(json_body, sizeof(json_body),
        "{"
        "\"agent_id\": \"%s\", "
        "\"hostname\": \"%s\", "
        "\"connection_status\": \"active\", "
        "\"ip_addresses\": %s, "
        "\"agent_version\": \"%s\", "
        "\"operating_system\": \"%s\", "
        "\"architecture\": \"%s\""
        "}",
        ctx->config->agent_id,
        ctx->config->hostname,
        ip_addresses_json,
        AGENT_VERSION,
        ctx->operating_system ? ctx->operating_system : "",
        ctx->architecture ? ctx->architecture : ""
    );

    utils_log_debug("Sending heartbeat to %s", heartbeat_url);

    /* Send HTTP POST */
    http_response_t *http_response = NULL;
    bool success = http_post(heartbeat_url, ctx->config->auth_token, json_body, &http_response);
    free(heartbeat_url);

    if (!success || http_response == NULL) {
        utils_log_error("[ERR_NETWORK_UNREACHABLE] Heartbeat request failed");
        if (http_response != NULL) {
            utils_log_error("HTTP error: %s", http_response->error_message);
            http_response_free(http_response);
        }
        return ERR_NETWORK_UNREACHABLE;
    }

    /* Check HTTP status */
    if (http_response->status_code == 401) {
        utils_log_error("[ERR_AUTH_FAILED] Authentication failed (HTTP 401)");
        utils_log_error("Context: Sending heartbeat to Agent Controller");
        utils_log_error("Root Cause: Invalid or missing auth_token");
        utils_log_error("Location: heartbeat.c:heartbeat_send()");
        utils_log_error("Fix: Verify auth_token in agent.conf matches Agent Controller token");
        http_response_free(http_response);
        return ERR_AUTH_FAILED;
    }

    if (http_response->status_code != 200) {
        utils_log_error("[ERR_SERVER_ERROR] Heartbeat failed with HTTP %d", http_response->status_code);
        utils_log_error("Response: %s", http_response->body);
        http_response_free(http_response);
        return ERR_SERVER_ERROR;
    }

    /* Parse response per FR-AC-007 */
    heartbeat_response_t *response = calloc(1, sizeof(heartbeat_response_t));
    if (response == NULL) {
        http_response_free(http_response);
        return ERR_INVALID_RESPONSE;
    }

    /* Parse JSON fields */
    char *status = NULL;
    if (http_parse_json_string(http_response->body, "status", &status)) {
        response->accepted = (strcmp(status, "accepted") == 0);
        free(status);
    }

    http_parse_json_bool(http_response->body, "config_updated", &response->config_updated);
    http_parse_json_int(http_response->body, "next_heartbeat_in_seconds", &response->next_heartbeat_in_seconds);
    http_parse_json_bool(http_response->body, "authorized", &response->authorized);

    /* Update agent context */
    ctx->authorized = response->authorized;
    ctx->last_heartbeat = utils_get_unix_timestamp();

    utils_log_info("Heartbeat sent successfully - authorized=%s",
                  response->authorized ? "true" : "false");

    http_response_free(http_response);
    *response_out = response;
    return ERR_SUCCESS;
}

void heartbeat_response_free(heartbeat_response_t *response) {
    free(response);
}

int heartbeat_send_with_retry(agent_context_t *ctx, heartbeat_response_t **response_out) {
    if (ctx == NULL || response_out == NULL) {
        return ERR_INVALID_RESPONSE;
    }

    int max_attempts = ctx->config->retry_attempts;
    int base_delay = ctx->config->retry_delay_seconds;
    int max_jitter = ctx->config->max_jitter_seconds * 1000; /* Convert to ms */

    for (int attempt = 1; attempt <= max_attempts; attempt++) {
        utils_log_debug("Heartbeat attempt %d/%d", attempt, max_attempts);

        int result = heartbeat_send(ctx, response_out);
        if (result == ERR_SUCCESS) {
            ctx->retry_count = 0;
            return ERR_SUCCESS;
        }

        /* Don't retry on authentication errors */
        if (result == ERR_AUTH_FAILED) {
            return result;
        }

        /* Calculate retry delay with exponential backoff per FR-AGENT-002 */
        if (attempt < max_attempts) {
            int backoff_multiplier = 1 << (attempt - 1); /* 2^(attempt-1) */
            int delay_seconds = base_delay * backoff_multiplier;
            int jitter_ms = utils_get_random_jitter_ms(max_jitter);

            utils_log_warn("Heartbeat failed, retrying in %d seconds (+ %d ms jitter)",
                          delay_seconds, jitter_ms);

            utils_sleep(delay_seconds);
            /* Add jitter (simplified - just add jitter as seconds) */
            if (jitter_ms > 0) {
                utils_sleep(jitter_ms / 1000);
            }
        }
    }

    ctx->retry_count++;
    utils_log_error("Heartbeat failed after %d attempts", max_attempts);
    return ERR_NETWORK_UNREACHABLE;
}
