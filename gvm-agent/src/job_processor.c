/**
 * GVM Agent - Job Processor Implementation
 * Per PRD Section 6.2 (FR-AGENT-003, FR-AGENT-004, FR-AGENT-006)
 */

#include "job_processor.h"
#include "http_client.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int job_poll(agent_context_t *ctx, job_list_t **jobs_out) {
    if (ctx == NULL || jobs_out == NULL) {
        return ERR_INVALID_RESPONSE;
    }

    /* Build jobs URL per FR-AC-008: GET /api/v1/agents/jobs */
    char *jobs_url = NULL;
    if (!utils_build_url(ctx->config->controller_url, "/api/v1/agents/jobs", &jobs_url)) {
        utils_log_error("[ERR_NETWORK_UNREACHABLE] Failed to build jobs URL");
        return ERR_NETWORK_UNREACHABLE;
    }

    utils_log_debug("Polling for jobs from %s", jobs_url);

    /* Send HTTP GET with X-Agent-ID header per FR-AC-008 */
    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        free(jobs_url);
        return ERR_NETWORK_UNREACHABLE;
    }

    http_response_t *http_response = NULL;

    /* We need to add X-Agent-ID header, so use manual curl setup */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");

    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", ctx->config->auth_token);
    headers = curl_slist_append(headers, auth_header);

    char agent_id_header[256];
    snprintf(agent_id_header, sizeof(agent_id_header), "X-Agent-ID: %s", ctx->config->agent_id);
    headers = curl_slist_append(headers, agent_id_header);

    http_response = calloc(1, sizeof(http_response_t));
    http_response->body = malloc(1);
    http_response->body[0] = '\0';
    http_response->body_size = 0;

    curl_easy_setopt(curl, CURLOPT_URL, jobs_url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, /* Use write_callback from http_client.c */);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)http_response);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        utils_log_error("[ERR_NETWORK_UNREACHABLE] Job polling failed: %s", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        http_response_free(http_response);
        free(jobs_url);
        return ERR_NETWORK_UNREACHABLE;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_response->status_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(jobs_url);

    if (http_response->status_code == 401) {
        utils_log_error("[ERR_AUTH_FAILED] Job polling authentication failed (HTTP 401)");
        http_response_free(http_response);
        return ERR_AUTH_FAILED;
    }

    if (http_response->status_code != 200) {
        utils_log_error("[ERR_SERVER_ERROR] Job polling failed with HTTP %d", http_response->status_code);
        http_response_free(http_response);
        return ERR_SERVER_ERROR;
    }

    /* Parse jobs array - simplified for Phase 1 */
    job_list_t *jobs = calloc(1, sizeof(job_list_t));
    if (jobs == NULL) {
        http_response_free(http_response);
        return ERR_INVALID_RESPONSE;
    }

    /* Simple check: if response contains "\"jobs\": []", no jobs available */
    if (strstr(http_response->body, "\"jobs\": []") != NULL ||
        strstr(http_response->body, "\"jobs\":[]") != NULL) {
        utils_log_debug("No jobs available");
        jobs->job_count = 0;
        jobs->jobs = NULL;
        http_response_free(http_response);
        *jobs_out = jobs;
        return ERR_SUCCESS;
    }

    /* For Phase 1, if there are jobs, just log them (full parsing in Phase 2) */
    utils_log_info("Jobs available: %s", http_response->body);

    /* Stub: Assume 1 job for testing */
    jobs->job_count = 0;  /* Set to 0 for Phase 1 MVP */
    jobs->jobs = NULL;

    http_response_free(http_response);
    *jobs_out = jobs;
    return ERR_SUCCESS;
}

int job_execute(agent_context_t *ctx, job_t *job, char **results_json_out) {
    if (ctx == NULL || job == NULL || results_json_out == NULL) {
        return ERR_JOB_EXECUTION_FAILED;
    }

    utils_log_info("Executing job %s (scan %s)", job->job_id, job->scan_id);

    /* Phase 1 Stub: Return mock results per FR-AGENT-004 */
    /* Full implementation in Phase 2: Execute NASL scripts */

    char *started_at = NULL;
    utils_get_iso8601_timestamp(&started_at);

    utils_sleep(5); /* Simulate scan time */

    char *completed_at = NULL;
    utils_get_iso8601_timestamp(&completed_at);

    /* Build results JSON per Section 6.1 FR-AC-009 */
    char results[4096];
    snprintf(results, sizeof(results),
        "{"
        "\"job_id\": \"%s\", "
        "\"scan_id\": \"%s\", "
        "\"agent_id\": \"%s\", "
        "\"status\": \"completed\", "
        "\"started_at\": \"%s\", "
        "\"completed_at\": \"%s\", "
        "\"results\": ["
        "  {"
        "    \"nvt\": {"
        "      \"oid\": \"1.3.6.1.4.1.25623.1.0.12345\", "
        "      \"name\": \"Test Vulnerability (Phase 1 Stub)\", "
        "      \"severity\": 5.0, "
        "      \"cvss_base_vector\": \"AV:N/AC:L/Au:N/C:N/I:N/A:N\""
        "    }, "
        "    \"host\": \"localhost\", "
        "    \"port\": \"22/tcp\", "
        "    \"threat\": \"Medium\", "
        "    \"description\": \"Phase 1 MVP: Stub result from agent\", "
        "    \"qod\": 80"
        "  }"
        "]"
        "}",
        job->job_id,
        job->scan_id,
        ctx->config->agent_id,
        started_at ? started_at : "",
        completed_at ? completed_at : ""
    );

    free(started_at);
    free(completed_at);

    *results_json_out = utils_strdup(results);
    utils_log_info("Job execution completed");
    return ERR_SUCCESS;
}

int job_submit_results(agent_context_t *ctx, const char *job_id, const char *scan_id, const char *results_json) {
    if (ctx == NULL || job_id == NULL || scan_id == NULL || results_json == NULL) {
        return ERR_JOB_EXECUTION_FAILED;
    }

    /* Build results URL per FR-AC-009: POST /api/v1/agents/jobs/{job_id}/results */
    char path[512];
    snprintf(path, sizeof(path), "/api/v1/agents/jobs/%s/results", job_id);

    char *results_url = NULL;
    if (!utils_build_url(ctx->config->controller_url, path, &results_url)) {
        utils_log_error("[ERR_NETWORK_UNREACHABLE] Failed to build results URL");
        return ERR_NETWORK_UNREACHABLE;
    }

    utils_log_debug("Submitting results to %s", results_url);

    /* Send HTTP POST */
    http_response_t *http_response = NULL;
    bool success = http_post(results_url, ctx->config->auth_token, results_json, &http_response);
    free(results_url);

    if (!success || http_response == NULL) {
        utils_log_error("[ERR_NETWORK_UNREACHABLE] Result submission failed");
        if (http_response != NULL) {
            http_response_free(http_response);
        }
        return ERR_NETWORK_UNREACHABLE;
    }

    if (http_response->status_code == 401) {
        utils_log_error("[ERR_AUTH_FAILED] Result submission authentication failed (HTTP 401)");
        http_response_free(http_response);
        return ERR_AUTH_FAILED;
    }

    if (http_response->status_code != 202) {
        utils_log_error("[ERR_SERVER_ERROR] Result submission failed with HTTP %d", http_response->status_code);
        utils_log_error("Response: %s", http_response->body);
        http_response_free(http_response);
        return ERR_SERVER_ERROR;
    }

    utils_log_info("Results submitted successfully for job %s", job_id);
    http_response_free(http_response);
    return ERR_SUCCESS;
}

void job_list_free(job_list_t *jobs) {
    if (jobs == NULL) {
        return;
    }

    for (int i = 0; i < jobs->job_count; i++) {
        job_free(&jobs->jobs[i]);
    }

    free(jobs->jobs);
    free(jobs);
}

void job_free(job_t *job) {
    if (job == NULL) {
        return;
    }

    free(job->job_id);
    free(job->scan_id);
    free(job->job_type);
    free(job->priority);
    free(job->created_at);
    free(job->config_json);
}
