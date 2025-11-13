/**
 * GVM Agent - Utility Functions Implementation
 */

#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#ifdef _WIN32
#include <windows.h>
#include <rpc.h>
#else
#include <unistd.h>
#include <uuid/uuid.h>
#endif

/* Log level */
static enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_ERROR = 3
} current_log_level = LOG_LEVEL_INFO;

void utils_log_init(const char *log_level) {
    if (log_level == NULL) {
        current_log_level = LOG_LEVEL_INFO;
        return;
    }

    if (strcmp(log_level, "debug") == 0) {
        current_log_level = LOG_LEVEL_DEBUG;
    } else if (strcmp(log_level, "info") == 0) {
        current_log_level = LOG_LEVEL_INFO;
    } else if (strcmp(log_level, "warn") == 0) {
        current_log_level = LOG_LEVEL_WARN;
    } else if (strcmp(log_level, "error") == 0) {
        current_log_level = LOG_LEVEL_ERROR;
    }
}

void utils_log_debug(const char *format, ...) {
    if (current_log_level > LOG_LEVEL_DEBUG) return;

    va_list args;
    fprintf(stdout, "[DEBUG] ");
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stdout);
}

void utils_log_info(const char *format, ...) {
    if (current_log_level > LOG_LEVEL_INFO) return;

    va_list args;
    fprintf(stdout, "[INFO] ");
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stdout);
}

void utils_log_warn(const char *format, ...) {
    if (current_log_level > LOG_LEVEL_WARN) return;

    va_list args;
    fprintf(stderr, "[WARN] ");
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
    fflush(stderr);
}

void utils_log_error(const char *format, ...) {
    if (current_log_level > LOG_LEVEL_ERROR) return;

    va_list args;
    fprintf(stderr, "[ERROR] ");
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
    fflush(stderr);
}

bool utils_generate_uuid(char **uuid_out) {
    if (uuid_out == NULL) {
        return false;
    }

    char *uuid_str = malloc(37);
    if (uuid_str == NULL) {
        return false;
    }

#ifdef _WIN32
    UUID uuid;
    RPC_CSTR uuid_cstr;

    if (UuidCreate(&uuid) != RPC_S_OK) {
        free(uuid_str);
        return false;
    }

    if (UuidToStringA(&uuid, &uuid_cstr) != RPC_S_OK) {
        free(uuid_str);
        return false;
    }

    strncpy(uuid_str, (char*)uuid_cstr, 36);
    uuid_str[36] = '\0';
    RpcStringFreeA(&uuid_cstr);
#else
    uuid_t uuid;
    uuid_generate_random(uuid);
    uuid_unparse_lower(uuid, uuid_str);
#endif

    *uuid_out = uuid_str;
    return true;
}

bool utils_get_iso8601_timestamp(char **timestamp_out) {
    if (timestamp_out == NULL) {
        return false;
    }

    time_t now = time(NULL);
    struct tm *tm_utc = gmtime(&now);

    char *timestamp = malloc(25);
    if (timestamp == NULL) {
        return false;
    }

    strftime(timestamp, 25, "%Y-%m-%dT%H:%M:%SZ", tm_utc);
    *timestamp_out = timestamp;
    return true;
}

long utils_get_unix_timestamp(void) {
    return (long)time(NULL);
}

void utils_sleep(int seconds) {
#ifdef _WIN32
    Sleep(seconds * 1000);
#else
    sleep(seconds);
#endif
}

int utils_get_random_jitter_ms(int max_jitter_ms) {
    if (max_jitter_ms <= 0) {
        return 0;
    }

    srand((unsigned int)time(NULL));
    return rand() % max_jitter_ms;
}

char* utils_strdup(const char *str) {
    if (str == NULL) {
        return NULL;
    }

    size_t len = strlen(str);
    char *dup = malloc(len + 1);
    if (dup == NULL) {
        return NULL;
    }

    strcpy(dup, str);
    return dup;
}

bool utils_build_url(const char *base, const char *path, char **url_out) {
    if (base == NULL || path == NULL || url_out == NULL) {
        return false;
    }

    size_t base_len = strlen(base);
    size_t path_len = strlen(path);
    bool needs_slash = (base_len > 0 && base[base_len - 1] != '/') && (path_len > 0 && path[0] != '/');

    size_t url_len = base_len + path_len + (needs_slash ? 1 : 0) + 1;
    char *url = malloc(url_len);
    if (url == NULL) {
        return false;
    }

    strcpy(url, base);
    if (needs_slash) {
        strcat(url, "/");
    }
    strcat(url, path);

    *url_out = url;
    return true;
}
