/**
 * GVM Agent - HTTP Client Implementation
 * Per PRD Section 7.2.1 - Uses libcurl for HTTPS communication
 */

#include "http_client.h"
#include "utils.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

/* Callback for writing response body */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    http_response_t *response = (http_response_t *)userp;

    char *ptr = realloc(response->body, response->body_size + realsize + 1);
    if (ptr == NULL) {
        utils_log_error("Failed to allocate memory for response body");
        return 0;
    }

    response->body = ptr;
    memcpy(&(response->body[response->body_size]), contents, realsize);
    response->body_size += realsize;
    response->body[response->body_size] = '\0';

    return realsize;
}

bool http_client_init(void) {
    CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (res != CURLE_OK) {
        utils_log_error("Failed to initialize libcurl: %s", curl_easy_strerror(res));
        return false;
    }

    utils_log_debug("HTTP client initialized");
    return true;
}

void http_client_cleanup(void) {
    curl_global_cleanup();
    utils_log_debug("HTTP client cleaned up");
}

static http_response_t* http_response_create(void) {
    http_response_t *response = calloc(1, sizeof(http_response_t));
    if (response == NULL) {
        return NULL;
    }

    response->body = malloc(1);
    if (response->body == NULL) {
        free(response);
        return NULL;
    }
    response->body[0] = '\0';
    response->body_size = 0;
    response->status_code = 0;

    return response;
}

void http_response_free(http_response_t *response) {
    if (response == NULL) {
        return;
    }

    free(response->body);
    free(response->error_message);
    free(response);
}

bool http_post(const char *url, const char *auth_token, const char *json_body, http_response_t **response_out) {
    if (url == NULL || json_body == NULL || response_out == NULL) {
        utils_log_error("HTTP POST: Invalid parameters");
        return false;
    }

    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        utils_log_error("Failed to initialize CURL handle");
        return false;
    }

    http_response_t *response = http_response_create();
    if (response == NULL) {
        curl_easy_cleanup(curl);
        return false;
    }

    /* Set URL */
    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* Set POST method */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);

    /* Set headers */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    if (auth_token != NULL) {
        char auth_header[512];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", auth_token);
        headers = curl_slist_append(headers, auth_header);
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* Set write callback */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);

    /* Enable TLS per SR-TLS-001 */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    /* Set timeout */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    utils_log_debug("HTTP POST to %s", url);
    utils_log_debug("Request body: %s", json_body);

    /* Perform request */
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        response->error_message = utils_strdup(curl_easy_strerror(res));
        utils_log_error("HTTP POST failed: %s", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        *response_out = response;
        return false;
    }

    /* Get HTTP status code */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->status_code);

    utils_log_debug("HTTP POST response: status=%d, body=%s", response->status_code, response->body);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    *response_out = response;
    return true;
}

bool http_get(const char *url, const char *auth_token, http_response_t **response_out) {
    if (url == NULL || response_out == NULL) {
        utils_log_error("HTTP GET: Invalid parameters");
        return false;
    }

    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        utils_log_error("Failed to initialize CURL handle");
        return false;
    }

    http_response_t *response = http_response_create();
    if (response == NULL) {
        curl_easy_cleanup(curl);
        return false;
    }

    /* Set URL */
    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* Set GET method */
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

    /* Set headers */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");

    if (auth_token != NULL) {
        char auth_header[512];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", auth_token);
        headers = curl_slist_append(headers, auth_header);
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* Set write callback */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);

    /* Enable TLS per SR-TLS-001 */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    /* Set timeout */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    utils_log_debug("HTTP GET to %s", url);

    /* Perform request */
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        response->error_message = utils_strdup(curl_easy_strerror(res));
        utils_log_error("HTTP GET failed: %s", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        *response_out = response;
        return false;
    }

    /* Get HTTP status code */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->status_code);

    utils_log_debug("HTTP GET response: status=%d, body=%s", response->status_code, response->body);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    *response_out = response;
    return true;
}

/* Simple JSON parser helpers (minimal implementation for Phase 1) */
bool http_parse_json_string(const char *json_str, const char *key, char **value_out) {
    if (json_str == NULL || key == NULL || value_out == NULL) {
        return false;
    }

    char search_key[256];
    snprintf(search_key, sizeof(search_key), "\"%s\"", key);

    const char *key_pos = strstr(json_str, search_key);
    if (key_pos == NULL) {
        return false;
    }

    const char *colon = strchr(key_pos, ':');
    if (colon == NULL) {
        return false;
    }

    const char *value_start = colon + 1;
    while (*value_start == ' ' || *value_start == '\t') {
        value_start++;
    }

    if (*value_start == '"') {
        value_start++;
        const char *value_end = strchr(value_start, '"');
        if (value_end == NULL) {
            return false;
        }

        size_t value_len = value_end - value_start;
        char *value = malloc(value_len + 1);
        if (value == NULL) {
            return false;
        }

        strncpy(value, value_start, value_len);
        value[value_len] = '\0';

        *value_out = value;
        return true;
    }

    return false;
}

bool http_parse_json_bool(const char *json_str, const char *key, bool *value_out) {
    if (json_str == NULL || key == NULL || value_out == NULL) {
        return false;
    }

    char search_key[256];
    snprintf(search_key, sizeof(search_key), "\"%s\"", key);

    const char *key_pos = strstr(json_str, search_key);
    if (key_pos == NULL) {
        return false;
    }

    const char *colon = strchr(key_pos, ':');
    if (colon == NULL) {
        return false;
    }

    const char *value_start = colon + 1;
    while (*value_start == ' ' || *value_start == '\t') {
        value_start++;
    }

    if (strncmp(value_start, "true", 4) == 0) {
        *value_out = true;
        return true;
    } else if (strncmp(value_start, "false", 5) == 0) {
        *value_out = false;
        return true;
    }

    return false;
}

bool http_parse_json_int(const char *json_str, const char *key, int *value_out) {
    if (json_str == NULL || key == NULL || value_out == NULL) {
        return false;
    }

    char search_key[256];
    snprintf(search_key, sizeof(search_key), "\"%s\"", key);

    const char *key_pos = strstr(json_str, search_key);
    if (key_pos == NULL) {
        return false;
    }

    const char *colon = strchr(key_pos, ':');
    if (colon == NULL) {
        return false;
    }

    const char *value_start = colon + 1;
    *value_out = atoi(value_start);

    return true;
}
