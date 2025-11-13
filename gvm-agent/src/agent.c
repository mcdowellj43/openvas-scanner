/**
 * GVM Agent - Main Agent Logic Implementation
 * Per PRD Section 7.2 - Host-Based Agent
 */

#include "agent.h"
#include "config.h"
#include "http_client.h"
#include "heartbeat.h"
#include "job_processor.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/utsname.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

int agent_get_system_info(char **os_out, char **arch_out, char ***ips_out, int *ip_count_out) {
    if (os_out == NULL || arch_out == NULL || ips_out == NULL || ip_count_out == NULL) {
        return ERR_INVALID_RESPONSE;
    }

    /* Get operating system */
#ifdef _WIN32
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((OSVERSIONINFO*)&osvi);

    char os[256];
    snprintf(os, sizeof(os), "Windows %lu.%lu", osvi.dwMajorVersion, osvi.dwMinorVersion);
    *os_out = utils_strdup(os);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        *arch_out = utils_strdup("amd64");
    } else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
        *arch_out = utils_strdup("arm64");
    } else {
        *arch_out = utils_strdup("x86");
    }
#else
    struct utsname un;
    if (uname(&un) == 0) {
        char os[256];
        snprintf(os, sizeof(os), "%s %s", un.sysname, un.release);
        *os_out = utils_strdup(os);
        *arch_out = utils_strdup(un.machine);
    } else {
        *os_out = utils_strdup("Unknown");
        *arch_out = utils_strdup("Unknown");
    }
#endif

    /* Get IP addresses */
    char **ip_addresses = malloc(sizeof(char*) * 16); /* Max 16 IPs */
    int ip_count = 0;

#ifdef _WIN32
    ULONG adapter_size = 15000;
    PIP_ADAPTER_ADDRESSES adapter_addresses = malloc(adapter_size);

    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, adapter_addresses, &adapter_size) == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES adapter = adapter_addresses;
        while (adapter && ip_count < 16) {
            PIP_ADAPTER_UNICAST_ADDRESS unicast = adapter->FirstUnicastAddress;
            while (unicast && ip_count < 16) {
                if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                    struct sockaddr_in *sa = (struct sockaddr_in *)unicast->Address.lpSockaddr;
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &sa->sin_addr, ip, INET_ADDRSTRLEN);
                    ip_addresses[ip_count++] = utils_strdup(ip);
                }
                unicast = unicast->Next;
            }
            adapter = adapter->Next;
        }
    }
    free(adapter_addresses);
#else
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == 0) {
        for (ifa = ifaddr; ifa != NULL && ip_count < 16; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;

            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sa->sin_addr, ip, INET_ADDRSTRLEN);

                /* Skip loopback */
                if (strcmp(ip, "127.0.0.1") != 0) {
                    ip_addresses[ip_count++] = utils_strdup(ip);
                }
            }
        }
        freeifaddrs(ifaddr);
    }
#endif

    /* Always include at least one IP */
    if (ip_count == 0) {
        ip_addresses[ip_count++] = utils_strdup("127.0.0.1");
    }

    *ips_out = ip_addresses;
    *ip_count_out = ip_count;

    return ERR_SUCCESS;
}

int agent_get_or_generate_uuid(const char *config_path, char **uuid_out) {
    /* Per FR-AGENT-001: Agent generates UUID on first run if not configured */
    if (uuid_out == NULL) {
        return ERR_INVALID_RESPONSE;
    }

    /* Try to generate new UUID */
    if (!utils_generate_uuid(uuid_out)) {
        utils_log_error("Failed to generate UUID");
        return ERR_INVALID_RESPONSE;
    }

    utils_log_info("Generated new agent UUID: %s", *uuid_out);
    return ERR_SUCCESS;
}

agent_context_t* agent_init(const char *config_path) {
    /* Initialize logging */
    utils_log_init("info");

    utils_log_info("==========================================================");
    utils_log_info("GVM Agent v%s starting...", AGENT_VERSION);
    utils_log_info("==========================================================");

    /* Initialize HTTP client */
    if (!http_client_init()) {
        utils_log_error("Failed to initialize HTTP client");
        return NULL;
    }

    /* Load configuration per FR-AGENT-001 */
    agent_config_t *config = NULL;
    const char *conf_path = config_path ? config_path : config_get_default_path();

    utils_log_info("Loading configuration from: %s", conf_path);

    int load_result = config_load(conf_path, &config);
    if (load_result != ERR_SUCCESS) {
        return NULL;
    }

    /* Initialize logging with configured level */
    utils_log_init(config->log_level);

    /* Generate or load agent UUID per FR-AGENT-001 */
    if (config->agent_id == NULL || strlen(config->agent_id) == 0) {
        char *uuid = NULL;
        if (agent_get_or_generate_uuid(conf_path, &uuid) != ERR_SUCCESS) {
            config_free(config);
            return NULL;
        }
        config->agent_id = uuid;
    }

    /* Get hostname if not configured */
    if (config->hostname == NULL || strlen(config->hostname) == 0) {
        char hostname[256];
#ifdef _WIN32
        DWORD size = sizeof(hostname);
        GetComputerNameA(hostname, &size);
#else
        gethostname(hostname, sizeof(hostname));
#endif
        config->hostname = utils_strdup(hostname);
    }

    /* Create agent context */
    agent_context_t *ctx = calloc(1, sizeof(agent_context_t));
    if (ctx == NULL) {
        config_free(config);
        return NULL;
    }

    ctx->config = config;
    ctx->state = AGENT_STATE_INITIALIZING;
    ctx->authorized = false;
    ctx->last_heartbeat = 0;
    ctx->retry_count = 0;

    /* Get system information per FR-AGENT-001 */
    agent_get_system_info(
        &ctx->operating_system,
        &ctx->architecture,
        &ctx->ip_addresses,
        &ctx->ip_address_count
    );

    utils_log_info("Agent ID: %s", ctx->config->agent_id);
    utils_log_info("Hostname: %s", ctx->config->hostname);
    utils_log_info("Operating System: %s", ctx->operating_system);
    utils_log_info("Architecture: %s", ctx->architecture);
    utils_log_info("Controller URL: %s", ctx->config->controller_url);
    utils_log_info("Heartbeat Interval: %d seconds", ctx->config->heartbeat_interval_seconds);

    ctx->state = AGENT_STATE_REGISTERING;
    return ctx;
}

int agent_run(agent_context_t *ctx) {
    if (ctx == NULL) {
        return 1;
    }

    utils_log_info("Starting agent main loop...");

    /* Main loop per FR-AGENT-002 and FR-AGENT-003 */
    while (1) {
        /* Send heartbeat per FR-AGENT-002 */
        heartbeat_response_t *hb_response = NULL;
        int hb_result = heartbeat_send_with_retry(ctx, &hb_response);

        if (hb_result != ERR_SUCCESS) {
            utils_log_error("Heartbeat failed, will retry at next interval");
            utils_sleep(ctx->config->heartbeat_interval_seconds);
            continue;
        }

        /* Update state based on authorization per FR-AGENT-001 */
        if (!ctx->authorized) {
            if (ctx->state == AGENT_STATE_REGISTERING) {
                utils_log_info("Agent registered but not yet authorized");
                utils_log_info("Waiting for admin to authorize agent via Agent Controller");
            }
            ctx->state = AGENT_STATE_UNAUTHORIZED;
            heartbeat_response_free(hb_response);
            utils_sleep(ctx->config->heartbeat_interval_seconds);
            continue;
        }

        /* Agent is authorized, move to active state */
        if (ctx->state != AGENT_STATE_ACTIVE) {
            utils_log_info("Agent authorized! Moving to ACTIVE state");
            ctx->state = AGENT_STATE_ACTIVE;
        }

        heartbeat_response_free(hb_response);

        /* Poll for jobs per FR-AGENT-003 */
        job_list_t *jobs = NULL;
        int job_result = job_poll(ctx, &jobs);

        if (job_result == ERR_SUCCESS && jobs != NULL) {
            if (jobs->job_count > 0) {
                utils_log_info("Received %d job(s)", jobs->job_count);

                /* Execute jobs per FR-AGENT-004 */
                for (int i = 0; i < jobs->job_count; i++) {
                    job_t *job = &jobs->jobs[i];

                    utils_log_info("Executing job: %s", job->job_id);

                    char *results_json = NULL;
                    int exec_result = job_execute(ctx, job, &results_json);

                    if (exec_result == ERR_SUCCESS && results_json != NULL) {
                        /* Submit results per FR-AGENT-006 */
                        job_submit_results(ctx, job->job_id, job->scan_id, results_json);
                        free(results_json);
                    } else {
                        utils_log_error("Job execution failed for job %s", job->job_id);
                    }
                }
            }

            job_list_free(jobs);
        }

        /* Sleep until next heartbeat per FR-AGENT-002 */
        utils_log_debug("Sleeping for %d seconds until next heartbeat",
                       ctx->config->heartbeat_interval_seconds);
        utils_sleep(ctx->config->heartbeat_interval_seconds);
    }

    return 0;
}

void agent_cleanup(agent_context_t *ctx) {
    if (ctx == NULL) {
        return;
    }

    utils_log_info("Shutting down agent...");

    config_free(ctx->config);

    free(ctx->operating_system);
    free(ctx->architecture);

    if (ctx->ip_addresses != NULL) {
        for (int i = 0; i < ctx->ip_address_count; i++) {
            free(ctx->ip_addresses[i]);
        }
        free(ctx->ip_addresses);
    }

    free(ctx);

    http_client_cleanup();

    utils_log_info("Agent shutdown complete");
}
