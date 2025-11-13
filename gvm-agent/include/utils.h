/**
 * GVM Agent - Utility Functions Header
 */

#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdbool.h>

/**
 * Generate UUID v4
 * Per FR-AGENT-001: Agent generates UUID on first run
 *
 * @param uuid_out UUID string (37 bytes including null terminator, caller must free)
 * @return true on success
 */
bool utils_generate_uuid(char **uuid_out);

/**
 * Get current timestamp in ISO 8601 format
 * Example: "2025-01-15T10:30:45Z"
 *
 * @param timestamp_out Timestamp string (caller must free)
 * @return true on success
 */
bool utils_get_iso8601_timestamp(char **timestamp_out);

/**
 * Get current Unix timestamp
 *
 * @return Unix timestamp in seconds
 */
long utils_get_unix_timestamp(void);

/**
 * Sleep for specified seconds
 *
 * @param seconds Seconds to sleep
 */
void utils_sleep(int seconds);

/**
 * Get random jitter in milliseconds
 * Per FR-AGENT-002: Add jitter to retry delays
 *
 * @param max_jitter_ms Maximum jitter in milliseconds
 * @return Random jitter value between 0 and max_jitter_ms
 */
int utils_get_random_jitter_ms(int max_jitter_ms);

/**
 * String duplication (safe strdup)
 *
 * @param str String to duplicate
 * @return Duplicated string (caller must free) or NULL on error
 */
char* utils_strdup(const char *str);

/**
 * Build URL by joining base and path
 * Example: "https://controller.example.com" + "/api/v1/agents/heartbeat"
 *
 * @param base Base URL
 * @param path Path to append
 * @param url_out Full URL (caller must free)
 * @return true on success
 */
bool utils_build_url(const char *base, const char *path, char **url_out);

/**
 * Logging functions
 */
void utils_log_debug(const char *format, ...);
void utils_log_info(const char *format, ...);
void utils_log_warn(const char *format, ...);
void utils_log_error(const char *format, ...);

/**
 * Initialize logging
 *
 * @param log_level "debug", "info", "warn", "error"
 */
void utils_log_init(const char *log_level);

#endif /* UTILS_H */
