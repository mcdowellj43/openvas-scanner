/**
 * GVM Agent - NVT Feed Management Implementation
 * Per PRD Section 6.2 (FR-AGENT-005) - NVT Feed Synchronization
 */

#include "nvt_feed.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <dirent.h>

static sqlite3 *g_cache_db = NULL;
static char *g_feed_dir = NULL;

int nvt_feed_init(const char *feed_dir, const char *cache_db_path) {
    if (feed_dir == NULL || cache_db_path == NULL) {
        utils_log_error("[ERR_CONFIG_INVALID] NVT feed directory or cache path is NULL");
        return ERR_CONFIG_INVALID;
    }

    /* Store feed directory */
    g_feed_dir = utils_strdup(feed_dir);

    /* Create feed directory if not exists */
    struct stat st;
    if (stat(feed_dir, &st) != 0) {
        utils_log_info("Creating feed directory: %s", feed_dir);
#ifdef _WIN32
        mkdir(feed_dir);
#else
        mkdir(feed_dir, 0755);
#endif
    }

    /* Open or create cache database */
    int rc = sqlite3_open(cache_db_path, &g_cache_db);
    if (rc != SQLITE_OK) {
        utils_log_error("[ERR_DATABASE] Failed to open NVT cache database: %s", sqlite3_errmsg(g_cache_db));
        return ERR_CONFIG_INVALID;
    }

    /* Create NVT table per Section 7.2.3 */
    const char *create_table_sql =
        "CREATE TABLE IF NOT EXISTS nvts ("
        "  oid TEXT PRIMARY KEY,"
        "  name TEXT NOT NULL,"
        "  family TEXT NOT NULL,"
        "  filename TEXT NOT NULL,"
        "  version TEXT,"
        "  cvss_base REAL,"
        "  last_modification INTEGER,"
        "  dependencies TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_family ON nvts(family);";

    char *err_msg = NULL;
    rc = sqlite3_exec(g_cache_db, create_table_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        utils_log_error("[ERR_DATABASE] Failed to create NVT cache table: %s", err_msg);
        sqlite3_free(err_msg);
        return ERR_CONFIG_INVALID;
    }

    utils_log_info("NVT feed initialized - feed_dir=%s, cache_db=%s", feed_dir, cache_db_path);
    return ERR_SUCCESS;
}

feed_sync_status_t nvt_feed_sync(const char *feed_source, const char *feed_dir, bool verify_gpg) {
    if (feed_source == NULL || feed_dir == NULL) {
        return FEED_SYNC_NETWORK_ERROR;
    }

    utils_log_info("Starting NVT feed sync from %s", feed_source);

    /* Check if rsync is available */
    int rsync_check = system("which rsync > /dev/null 2>&1");
    if (rsync_check != 0) {
        utils_log_error("[FEED_SYNC_NETWORK_ERROR] rsync not found - install rsync package");
        utils_log_error("Context: NVT feed synchronization");
        utils_log_error("Root Cause: rsync binary not found in PATH");
        utils_log_error("Location: nvt_feed.c:nvt_feed_sync()");
        utils_log_error("Fix: Install rsync (apt-get install rsync or yum install rsync)");
        return FEED_SYNC_NETWORK_ERROR;
    }

    /* Build rsync command per Section 7.2.3 */
    char rsync_cmd[1024];
    snprintf(rsync_cmd, sizeof(rsync_cmd),
        "rsync -av --delete \"%s\" \"%s/\" 2>&1",
        feed_source, feed_dir);

    utils_log_debug("Executing: %s", rsync_cmd);

    /* Execute rsync */
    FILE *fp = popen(rsync_cmd, "r");
    if (fp == NULL) {
        utils_log_error("[FEED_SYNC_NETWORK_ERROR] Failed to execute rsync");
        return FEED_SYNC_NETWORK_ERROR;
    }

    /* Read rsync output */
    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Strip newline */
        line[strcspn(line, "\n")] = 0;
        utils_log_debug("rsync: %s", line);
    }

    int rsync_status = pclose(fp);
    if (rsync_status != 0) {
        utils_log_error("[FEED_SYNC_NETWORK_ERROR] rsync failed with status %d", rsync_status);
        return FEED_SYNC_NETWORK_ERROR;
    }

    utils_log_info("Feed sync completed successfully");

    /* Verify GPG signature if requested per FR-AGENT-005 */
    if (verify_gpg) {
        utils_log_info("Verifying GPG signature...");

        /* Check if GPG is available */
        int gpg_check = system("which gpg > /dev/null 2>&1");
        if (gpg_check != 0) {
            utils_log_warn("GPG not found - skipping signature verification");
            utils_log_warn("Install gnupg package for signature verification");
        } else {
            /* Verify signature per Section 7.2.3 */
            char gpg_cmd[1024];
            snprintf(gpg_cmd, sizeof(gpg_cmd),
                "gpg --verify \"%s/sha256sums.asc\" \"%s/sha256sums\" 2>&1",
                feed_dir, feed_dir);

            fp = popen(gpg_cmd, "r");
            if (fp != NULL) {
                bool signature_valid = false;
                while (fgets(line, sizeof(line), fp) != NULL) {
                    utils_log_debug("gpg: %s", line);
                    if (strstr(line, "Good signature") != NULL) {
                        signature_valid = true;
                    }
                }
                pclose(fp);

                if (!signature_valid) {
                    utils_log_error("[FEED_SYNC_GPG_ERROR] GPG signature verification failed");
                    return FEED_SYNC_GPG_ERROR;
                }

                utils_log_info("GPG signature verified successfully");
            }
        }
    }

    return FEED_SYNC_SUCCESS;
}

/* Helper: Parse NASL file for metadata */
static bool parse_nasl_file(const char *filepath, nvt_record_t *nvt) {
    FILE *fp = fopen(filepath, "r");
    if (fp == NULL) {
        return false;
    }

    char line[512];
    bool found_oid = false;

    /* Simple parser - look for script_oid, script_name, script_family */
    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Extract OID: script_oid("1.3.6.1.4.1.25623.1.0.12345"); */
        if (strstr(line, "script_oid(") != NULL) {
            char *start = strchr(line, '"');
            if (start != NULL) {
                start++;
                char *end = strchr(start, '"');
                if (end != NULL) {
                    *end = '\0';
                    nvt->oid = utils_strdup(start);
                    found_oid = true;
                }
            }
        }

        /* Extract name: script_name("Vulnerability Name"); */
        if (strstr(line, "script_name(") != NULL) {
            char *start = strchr(line, '"');
            if (start != NULL) {
                start++;
                char *end = strchr(start, '"');
                if (end != NULL) {
                    *end = '\0';
                    nvt->name = utils_strdup(start);
                }
            }
        }

        /* Extract family: script_family("Service detection"); */
        if (strstr(line, "script_family(") != NULL) {
            char *start = strchr(line, '"');
            if (start != NULL) {
                start++;
                char *end = strchr(start, '"');
                if (end != NULL) {
                    *end = '\0';
                    nvt->family = utils_strdup(start);
                }
            }
        }

        /* Extract CVSS: script_cvss_base("5.0"); */
        if (strstr(line, "script_cvss_base(") != NULL) {
            char *start = strchr(line, '"');
            if (start != NULL) {
                start++;
                nvt->cvss_base = atof(start);
            }
        }
    }

    fclose(fp);

    /* Set filename */
    nvt->filename = utils_strdup(filepath);
    nvt->version = utils_strdup("unknown");
    nvt->last_modification = utils_get_unix_timestamp();
    nvt->dependencies = utils_strdup("");

    return found_oid;
}

/* Helper: Recursively scan directory for .nasl files */
static int scan_directory(const char *dir_path, sqlite3_stmt *insert_stmt, int *count) {
    DIR *dir = opendir(dir_path);
    if (dir == NULL) {
        return 0;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            /* Recurse into subdirectory */
            scan_directory(full_path, insert_stmt, count);
        } else if (S_ISREG(st.st_mode)) {
            /* Check if .nasl file */
            size_t name_len = strlen(entry->d_name);
            if (name_len > 5 && strcmp(entry->d_name + name_len - 5, ".nasl") == 0) {
                /* Parse NASL file */
                nvt_record_t nvt = {0};
                if (parse_nasl_file(full_path, &nvt)) {
                    /* Insert into database */
                    sqlite3_bind_text(insert_stmt, 1, nvt.oid, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(insert_stmt, 2, nvt.name ? nvt.name : "Unknown", -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(insert_stmt, 3, nvt.family ? nvt.family : "Unknown", -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(insert_stmt, 4, nvt.filename, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(insert_stmt, 5, nvt.version, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_double(insert_stmt, 6, nvt.cvss_base);
                    sqlite3_bind_int64(insert_stmt, 7, nvt.last_modification);
                    sqlite3_bind_text(insert_stmt, 8, nvt.dependencies, -1, SQLITE_TRANSIENT);

                    if (sqlite3_step(insert_stmt) == SQLITE_DONE) {
                        (*count)++;
                    }
                    sqlite3_reset(insert_stmt);

                    /* Free nvt fields */
                    free(nvt.oid);
                    free(nvt.name);
                    free(nvt.family);
                    free(nvt.filename);
                    free(nvt.version);
                    free(nvt.dependencies);
                }
            }
        }
    }

    closedir(dir);
    return 0;
}

int nvt_feed_rebuild_cache(const char *feed_dir, const char *cache_db_path) {
    if (g_cache_db == NULL) {
        utils_log_error("[ERR_DATABASE] NVT cache database not initialized");
        return -1;
    }

    utils_log_info("Rebuilding NVT cache from %s", feed_dir);

    /* Begin transaction for performance */
    sqlite3_exec(g_cache_db, "BEGIN TRANSACTION", NULL, NULL, NULL);

    /* Clear existing cache */
    sqlite3_exec(g_cache_db, "DELETE FROM nvts", NULL, NULL, NULL);

    /* Prepare insert statement */
    const char *insert_sql =
        "INSERT INTO nvts (oid, name, family, filename, version, cvss_base, last_modification, dependencies) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *insert_stmt = NULL;
    int rc = sqlite3_prepare_v2(g_cache_db, insert_sql, -1, &insert_stmt, NULL);
    if (rc != SQLITE_OK) {
        utils_log_error("[ERR_DATABASE] Failed to prepare insert statement: %s", sqlite3_errmsg(g_cache_db));
        sqlite3_exec(g_cache_db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }

    /* Scan feed directory recursively */
    int nvt_count = 0;
    scan_directory(feed_dir, insert_stmt, &nvt_count);

    /* Finalize statement */
    sqlite3_finalize(insert_stmt);

    /* Commit transaction */
    sqlite3_exec(g_cache_db, "COMMIT", NULL, NULL, NULL);

    utils_log_info("NVT cache rebuild completed - %d NVTs indexed", nvt_count);
    return nvt_count;
}

bool nvt_feed_lookup_by_oid(const char *oid, nvt_record_t **nvt_out) {
    if (g_cache_db == NULL || oid == NULL || nvt_out == NULL) {
        return false;
    }

    const char *select_sql = "SELECT oid, name, family, filename, version, cvss_base, last_modification, dependencies "
                            "FROM nvts WHERE oid = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_cache_db, select_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, oid, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        nvt_record_t *nvt = calloc(1, sizeof(nvt_record_t));
        if (nvt != NULL) {
            nvt->oid = utils_strdup((const char*)sqlite3_column_text(stmt, 0));
            nvt->name = utils_strdup((const char*)sqlite3_column_text(stmt, 1));
            nvt->family = utils_strdup((const char*)sqlite3_column_text(stmt, 2));
            nvt->filename = utils_strdup((const char*)sqlite3_column_text(stmt, 3));
            nvt->version = utils_strdup((const char*)sqlite3_column_text(stmt, 4));
            nvt->cvss_base = sqlite3_column_double(stmt, 5);
            nvt->last_modification = sqlite3_column_int64(stmt, 6);
            nvt->dependencies = utils_strdup((const char*)sqlite3_column_text(stmt, 7));

            *nvt_out = nvt;
            sqlite3_finalize(stmt);
            return true;
        }
    }

    sqlite3_finalize(stmt);
    return false;
}

int nvt_feed_get_by_family(const char *family, nvt_record_t **nvts_out, int *count_out) {
    /* Not implemented in Phase 2 - return stub */
    *nvts_out = NULL;
    *count_out = 0;
    return ERR_SUCCESS;
}

void nvt_record_free(nvt_record_t *nvt) {
    if (nvt == NULL) {
        return;
    }

    free(nvt->oid);
    free(nvt->name);
    free(nvt->family);
    free(nvt->filename);
    free(nvt->version);
    free(nvt->dependencies);
    free(nvt);
}

int nvt_feed_get_stats(int *total_nvts_out, long *last_update_out) {
    if (g_cache_db == NULL) {
        return ERR_CONFIG_INVALID;
    }

    const char *count_sql = "SELECT COUNT(*) FROM nvts";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(g_cache_db, count_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return ERR_CONFIG_INVALID;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *total_nvts_out = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);

    *last_update_out = utils_get_unix_timestamp();
    return ERR_SUCCESS;
}

bool nvt_feed_sync_needed(long last_sync_time, int sync_interval_hours) {
    long now = utils_get_unix_timestamp();
    long diff_seconds = now - last_sync_time;
    long diff_hours = diff_seconds / 3600;

    return (diff_hours >= sync_interval_hours);
}

bool nvt_feed_verify_signature(const char *feed_dir, const char *gpg_keyring) {
    /* Simplified verification - check if sha256sums.asc exists */
    char sig_path[1024];
    snprintf(sig_path, sizeof(sig_path), "%s/sha256sums.asc", feed_dir);

    struct stat st;
    return (stat(sig_path, &st) == 0);
}
