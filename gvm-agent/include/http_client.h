/**
 * GVM Agent - HTTP Client Header
 * Per PRD Section 7.2.1 - Uses libcurl for HTTPS communication
 *
 * Implements HTTP client for Agent-Facing API (Section 8.3):
 * - POST /api/v1/agents/heartbeat
 * - GET /api/v1/agents/jobs
 * - POST /api/v1/agents/jobs/{id}/results
 */

#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stddef.h>
#include <stdbool.h>

/* HTTP response structure */
typedef struct {
    int status_code;
    char *body;
    size_t body_size;
    char *error_message;
} http_response_t;

/**
 * Initialize HTTP client library
 * Per Section 7.2.1: Uses libcurl
 *
 * @return true on success
 */
bool http_client_init(void);

/**
 * Cleanup HTTP client library
 */
void http_client_cleanup(void);

/**
 * Send HTTP POST request
 * Per SR-TLS-001: Mandatory TLS 1.3
 * Per SR-AUTH-001: Bearer token authentication
 *
 * @param url Full URL including protocol
 * @param auth_token Bearer token (NULL if not required)
 * @param json_body JSON body string
 * @param response_out Response structure (caller must free with http_response_free)
 * @return true on success (check response->status_code for HTTP status)
 */
bool http_post(const char *url, const char *auth_token, const char *json_body, http_response_t **response_out);

/**
 * Send HTTP GET request
 * Per SR-TLS-001: Mandatory TLS 1.3
 * Per SR-AUTH-001: Bearer token authentication
 *
 * @param url Full URL including protocol
 * @param auth_token Bearer token (NULL if not required)
 * @param response_out Response structure (caller must free with http_response_free)
 * @return true on success (check response->status_code for HTTP status)
 */
bool http_get(const char *url, const char *auth_token, http_response_t **response_out);

/**
 * Free HTTP response
 *
 * @param response Response to free
 */
void http_response_free(http_response_t *response);

/**
 * Parse JSON response body
 * Helper function to extract values from JSON response
 *
 * @param json_str JSON string
 * @param key Key to extract
 * @param value_out Value string (caller must free)
 * @return true if key found
 */
bool http_parse_json_string(const char *json_str, const char *key, char **value_out);

/**
 * Parse JSON boolean value
 *
 * @param json_str JSON string
 * @param key Key to extract
 * @param value_out Boolean value
 * @return true if key found
 */
bool http_parse_json_bool(const char *json_str, const char *key, bool *value_out);

/**
 * Parse JSON integer value
 *
 * @param json_str JSON string
 * @param key Key to extract
 * @param value_out Integer value
 * @return true if key found
 */
bool http_parse_json_int(const char *json_str, const char *key, int *value_out);

#endif /* HTTP_CLIENT_H */
