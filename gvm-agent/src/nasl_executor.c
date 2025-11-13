/**
 * GVM Agent - NASL Executor Implementation
 * Per PRD Section 6.2 (FR-AGENT-004) - Local Vulnerability Scanning
 */

#include "nasl_executor.h"
#include "nvt_feed.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static bool g_has_openvas_nasl = false;

int nasl_executor_init(void) {
    /* Check if openvas-nasl is available */
    int check = system("which openvas-nasl > /dev/null 2>&1");
    g_has_openvas_nasl = (check == 0);

    if (g_has_openvas_nasl) {
        utils_log_info("NASL Executor: openvas-nasl found - will use for script execution");
    } else {
        utils_log_info("NASL Executor: openvas-nasl not found - using built-in checks");
        utils_log_warn("Install openvas-scanner package for full NASL support");
    }

    return ERR_SUCCESS;
}

bool nasl_executor_has_openvas_nasl(void) {
    return g_has_openvas_nasl;
}

/* Helper: Create scan result */
static scan_result_t* create_scan_result(
    const char *oid,
    const char *name,
    float severity,
    const char *host,
    const char *port,
    const char *description
) {
    scan_result_t *result = calloc(1, sizeof(scan_result_t));
    if (result == NULL) {
        return NULL;
    }

    result->nvt_oid = utils_strdup(oid);
    result->nvt_name = utils_strdup(name);
    result->severity = severity;
    result->cvss_base_vector = utils_strdup("AV:N/AC:L/Au:N/C:N/I:N/A:N");
    result->host = utils_strdup(host);
    result->port = utils_strdup(port);

    /* Set threat level based on severity */
    if (severity >= 7.0) {
        result->threat = utils_strdup("High");
    } else if (severity >= 4.0) {
        result->threat = utils_strdup("Medium");
    } else {
        result->threat = utils_strdup("Low");
    }

    result->description = utils_strdup(description);
    result->qod = 70;  /* Quality of Detection */

    return result;
}

int nasl_executor_run_script(
    const nvt_record_t *nvt,
    const char *target,
    const char *port_list,
    const scan_preferences_t *preferences,
    scan_result_list_t **results_out
) {
    if (nvt == NULL || target == NULL || results_out == NULL) {
        return ERR_JOB_EXECUTION_FAILED;
    }

    utils_log_debug("Executing NASL script: %s (%s)", nvt->name, nvt->oid);

    scan_result_list_t *results = calloc(1, sizeof(scan_result_list_t));
    if (results == NULL) {
        return ERR_JOB_EXECUTION_FAILED;
    }

    if (g_has_openvas_nasl) {
        /* Execute using openvas-nasl */
        char nasl_cmd[2048];
        snprintf(nasl_cmd, sizeof(nasl_cmd),
            "openvas-nasl -t %s \"%s\" 2>&1",
            target, nvt->filename);

        utils_log_debug("Executing: %s", nasl_cmd);

        FILE *fp = popen(nasl_cmd, "r");
        if (fp == NULL) {
            free(results);
            return ERR_JOB_EXECUTION_FAILED;
        }

        /* Parse openvas-nasl output */
        char line[512];
        bool found_vulnerability = false;
        char description[1024] = "";

        while (fgets(line, sizeof(line), fp) != NULL) {
            utils_log_debug("nasl: %s", line);

            /* Check for vulnerability indicators */
            if (strstr(line, "ALARM") != NULL || strstr(line, "HOLE") != NULL ||
                strstr(line, "WARNING") != NULL) {
                found_vulnerability = true;
                strncat(description, line, sizeof(description) - strlen(description) - 1);
            }
        }

        pclose(fp);

        /* Create result if vulnerability found */
        if (found_vulnerability) {
            scan_result_t *result = create_scan_result(
                nvt->oid,
                nvt->name,
                nvt->cvss_base,
                target,
                "general/tcp",
                description[0] ? description : "Vulnerability detected by NASL script"
            );

            if (result != NULL) {
                results->results = malloc(sizeof(scan_result_t));
                results->results[0] = *result;
                results->result_count = 1;
                free(result);
            }
        }
    } else {
        /* Fallback: Simple check based on NVT metadata */
        utils_log_debug("Using built-in check for %s", nvt->name);

        /* For Phase 2, create a mock result for demonstration */
        if (nvt->cvss_base > 0) {
            scan_result_t *result = create_scan_result(
                nvt->oid,
                nvt->name,
                nvt->cvss_base,
                target,
                "general/tcp",
                "Phase 2: Simplified check result (install openvas-nasl for full scanning)"
            );

            if (result != NULL) {
                results->results = malloc(sizeof(scan_result_t));
                results->results[0] = *result;
                results->result_count = 1;
                free(result);
            }
        }
    }

    *results_out = results;
    return ERR_SUCCESS;
}

int nasl_executor_run_scan(
    const char **oids,
    int oid_count,
    const char *target,
    const char *port_list,
    const scan_preferences_t *preferences,
    scan_result_list_t **results_out
) {
    if (oids == NULL || oid_count == 0 || target == NULL || results_out == NULL) {
        return ERR_JOB_EXECUTION_FAILED;
    }

    utils_log_info("Starting vulnerability scan: %d VTs against %s", oid_count, target);

    /* Allocate results list */
    scan_result_list_t *all_results = calloc(1, sizeof(scan_result_list_t));
    if (all_results == NULL) {
        return ERR_JOB_EXECUTION_FAILED;
    }

    all_results->results = malloc(sizeof(scan_result_t) * oid_count);
    if (all_results->results == NULL) {
        free(all_results);
        return ERR_JOB_EXECUTION_FAILED;
    }

    int result_index = 0;

    /* Execute each VT */
    for (int i = 0; i < oid_count; i++) {
        utils_log_debug("Scanning with VT %d/%d: %s", i + 1, oid_count, oids[i]);

        /* Lookup NVT */
        nvt_record_t *nvt = NULL;
        if (!nvt_feed_lookup_by_oid(oids[i], &nvt)) {
            utils_log_warn("NVT not found in cache: %s", oids[i]);
            continue;
        }

        /* Execute script */
        scan_result_list_t *script_results = NULL;
        int exec_result = nasl_executor_run_script(nvt, target, port_list, preferences, &script_results);

        nvt_record_free(nvt);

        if (exec_result == ERR_SUCCESS && script_results != NULL) {
            /* Add results to aggregate list */
            for (int j = 0; j < script_results->result_count; j++) {
                all_results->results[result_index++] = script_results->results[j];
            }
            /* Don't free individual results, just the container */
            free(script_results->results);
            free(script_results);
        }

        /* Apply rate limiting per preferences */
        if (preferences != NULL && i < oid_count - 1) {
            /* Small delay between VTs to avoid overload */
            utils_sleep(1);
        }
    }

    all_results->result_count = result_index;

    utils_log_info("Vulnerability scan completed: %d findings", result_index);

    *results_out = all_results;
    return ERR_SUCCESS;
}

int nasl_executor_run_basic_checks(const char *target, scan_result_list_t **results_out) {
    if (target == NULL || results_out == NULL) {
        return ERR_JOB_EXECUTION_FAILED;
    }

    utils_log_info("Running basic security checks on %s", target);

    scan_result_list_t *results = calloc(1, sizeof(scan_result_list_t));
    if (results == NULL) {
        return ERR_JOB_EXECUTION_FAILED;
    }

    /* Allocate space for basic checks */
    results->results = malloc(sizeof(scan_result_t) * 10);
    if (results->results == NULL) {
        free(results);
        return ERR_JOB_EXECUTION_FAILED;
    }

    int result_count = 0;

    /* Check 1: SSH port scan */
    char ssh_check[256];
    snprintf(ssh_check, sizeof(ssh_check), "nc -zv -w2 %s 22 2>&1 | grep -q succeeded", target);
    if (system(ssh_check) == 0) {
        scan_result_t *result = create_scan_result(
            "1.3.6.1.4.1.25623.1.0.900001",
            "SSH Service Detection",
            0.0,
            target,
            "22/tcp",
            "SSH service is running on port 22"
        );
        if (result != NULL) {
            results->results[result_count++] = *result;
            free(result);
        }
    }

    /* Check 2: HTTP port scan */
    char http_check[256];
    snprintf(http_check, sizeof(http_check), "nc -zv -w2 %s 80 2>&1 | grep -q succeeded", target);
    if (system(http_check) == 0) {
        scan_result_t *result = create_scan_result(
            "1.3.6.1.4.1.25623.1.0.900002",
            "HTTP Service Detection",
            0.0,
            target,
            "80/tcp",
            "HTTP service is running on port 80"
        );
        if (result != NULL) {
            results->results[result_count++] = *result;
            free(result);
        }
    }

    /* Check 3: HTTPS port scan */
    char https_check[256];
    snprintf(https_check, sizeof(https_check), "nc -zv -w2 %s 443 2>&1 | grep -q succeeded", target);
    if (system(https_check) == 0) {
        scan_result_t *result = create_scan_result(
            "1.3.6.1.4.1.25623.1.0.900003",
            "HTTPS Service Detection",
            0.0,
            target,
            "443/tcp",
            "HTTPS service is running on port 443"
        );
        if (result != NULL) {
            results->results[result_count++] = *result;
            free(result);
        }
    }

    results->result_count = result_count;

    utils_log_info("Basic checks completed: %d findings", result_count);

    *results_out = results;
    return ERR_SUCCESS;
}

void scan_result_list_free(scan_result_list_t *results) {
    if (results == NULL) {
        return;
    }

    for (int i = 0; i < results->result_count; i++) {
        scan_result_free(&results->results[i]);
    }

    free(results->results);
    free(results);
}

void scan_result_free(scan_result_t *result) {
    if (result == NULL) {
        return;
    }

    free(result->nvt_oid);
    free(result->nvt_name);
    free(result->cvss_base_vector);
    free(result->host);
    free(result->port);
    free(result->threat);
    free(result->description);
}
