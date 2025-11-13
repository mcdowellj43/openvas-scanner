/**
 * GVM Agent - NVT Feed Management Header
 * Per PRD Section 6.2 (FR-AGENT-005) - NVT Feed Synchronization
 *
 * Implements:
 * - Feed synchronization via rsync
 * - GPG signature verification
 * - NVT cache database (SQLite)
 * - OID index rebuilding
 */

#ifndef NVT_FEED_H
#define NVT_FEED_H

#include "agent.h"
#include <stdbool.h>

/* NVT record structure */
typedef struct {
    char *oid;
    char *name;
    char *family;
    char *filename;
    char *version;
    float cvss_base;
    long last_modification;
    char *dependencies;  /* Comma-separated OIDs */
} nvt_record_t;

/* Feed sync status */
typedef enum {
    FEED_SYNC_SUCCESS = 0,
    FEED_SYNC_NETWORK_ERROR = 1,
    FEED_SYNC_GPG_ERROR = 2,
    FEED_SYNC_DISK_ERROR = 3,
    FEED_SYNC_INDEX_ERROR = 4
} feed_sync_status_t;

/**
 * Initialize NVT feed management
 * Creates cache database if not exists per Section 7.2.3
 *
 * @param feed_dir Local feed directory (e.g., /opt/gvm-agent/plugins)
 * @param cache_db_path Path to cache database (e.g., /var/lib/gvm-agent/nvt_cache.db)
 * @return ERR_SUCCESS or error code
 */
int nvt_feed_init(const char *feed_dir, const char *cache_db_path);

/**
 * Synchronize NVT feed from remote source
 * Per FR-AGENT-005: NVT Feed Synchronization
 *
 * Sync Flow per Section 6.2:
 * 1. Check feed source (rsync or HTTP)
 * 2. Sync feed to local directory
 * 3. Verify GPG signature
 * 4. Rebuild OID index
 * 5. Log sync completion
 *
 * @param feed_source Feed URL (rsync://feed.community.greenbone.net/nvt-feed)
 * @param feed_dir Local feed directory
 * @param verify_gpg Verify GPG signatures (true/false)
 * @return feed_sync_status_t
 */
feed_sync_status_t nvt_feed_sync(const char *feed_source, const char *feed_dir, bool verify_gpg);

/**
 * Rebuild NVT cache from feed files
 * Per Section 7.2.3: Parse .nasl files and build OID index
 *
 * Creates SQLite database per Section 7.2.3:
 * - Table: nvts (oid, name, family, filename, version, cvss_base, last_modification, dependencies)
 * - Index: idx_family (family)
 *
 * @param feed_dir Feed directory to scan
 * @param cache_db_path Cache database path
 * @return Number of NVTs indexed or -1 on error
 */
int nvt_feed_rebuild_cache(const char *feed_dir, const char *cache_db_path);

/**
 * Lookup NVT by OID
 * Per FR-AGENT-004: Agents need to lookup VTs by OID to execute them
 *
 * @param oid NVT OID (e.g., "1.3.6.1.4.1.25623.1.0.10662")
 * @param nvt_out NVT record (caller must free with nvt_record_free)
 * @return true if found
 */
bool nvt_feed_lookup_by_oid(const char *oid, nvt_record_t **nvt_out);

/**
 * Get all NVTs in a family
 *
 * @param family Family name (e.g., "Service detection")
 * @param nvts_out Array of NVT records (caller must free)
 * @param count_out Number of NVTs
 * @return ERR_SUCCESS or error code
 */
int nvt_feed_get_by_family(const char *family, nvt_record_t **nvts_out, int *count_out);

/**
 * Free NVT record
 *
 * @param nvt NVT record to free
 */
void nvt_record_free(nvt_record_t *nvt);

/**
 * Get feed statistics
 *
 * @param total_nvts_out Total NVTs in cache
 * @param last_update_out Last feed update timestamp
 * @return ERR_SUCCESS or error code
 */
int nvt_feed_get_stats(int *total_nvts_out, long *last_update_out);

/**
 * Check if feed sync is needed
 * Per FR-AGENT-005: Sync schedule (default: daily at 2 AM)
 *
 * @param last_sync_time Last successful sync timestamp
 * @param sync_interval_hours Sync interval in hours (default: 24)
 * @return true if sync is needed
 */
bool nvt_feed_sync_needed(long last_sync_time, int sync_interval_hours);

/**
 * Verify GPG signature of feed
 * Per FR-AGENT-005: Feed must be verified with GPG
 *
 * @param feed_dir Feed directory
 * @param gpg_keyring GPG keyring path
 * @return true if signature valid
 */
bool nvt_feed_verify_signature(const char *feed_dir, const char *gpg_keyring);

#endif /* NVT_FEED_H */
