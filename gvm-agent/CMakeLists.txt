# GVM Agent Build System - Phase 2
# Per PRD Section 7.2 - Host-Based Agent Technical Requirements
#
# Phase 1 + Phase 2 Features:
# - FR-AGENT-001: Agent Registration
# - FR-AGENT-002: Periodic Heartbeat
# - FR-AGENT-003: Job Polling
# - FR-AGENT-004: Local Vulnerability Scanning (Phase 2: Full NASL)
# - FR-AGENT-005: NVT Feed Synchronization (Phase 2: rsync + GPG)
# - FR-AGENT-006: Result Submission
# - FR-AGENT-008: Auto-Update (Phase 2)

cmake_minimum_required(VERSION 3.10)
project(gvm-agent C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Version information
set(AGENT_VERSION_MAJOR 2)
set(AGENT_VERSION_MINOR 0)
set(AGENT_VERSION_PATCH 0)
set(AGENT_VERSION "${AGENT_VERSION_MAJOR}.${AGENT_VERSION_MINOR}.${AGENT_VERSION_PATCH}")

# Build options
option(BUILD_WINDOWS "Build for Windows" OFF)
option(BUILD_LINUX "Build for Linux" ON)
option(BUILD_MACOS "Build for macOS" OFF)

# Find required libraries per Section 7.2.1
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

# Find SQLite3 for NVT cache (Phase 2)
find_package(SQLite3 REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CURL_INCLUDE_DIRS}
    ${SQLite3_INCLUDE_DIRS}
)

# Source files (Phase 1 + Phase 2)
set(AGENT_SOURCES
    src/main.c
    src/agent.c
    src/config.c
    src/http_client.c
    src/heartbeat.c
    src/job_processor.c
    src/utils.c
    src/nvt_feed.c
    src/nasl_executor.c
    src/auto_update.c
)

# Header files (Phase 1 + Phase 2)
set(AGENT_HEADERS
    include/agent.h
    include/config.h
    include/http_client.h
    include/heartbeat.h
    include/job_processor.h
    include/utils.h
    include/nvt_feed.h
    include/nasl_executor.h
    include/auto_update.h
)

# Create agent executable
add_executable(gvm-agent ${AGENT_SOURCES} ${AGENT_HEADERS})

# Link libraries per Section 7.2.1 (Phase 1 + Phase 2)
target_link_libraries(gvm-agent
    ${CURL_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    ${SQLite3_LIBRARIES}
)

# Platform-specific settings
if(WIN32)
    # Windows-specific settings per Section 7.2.5
    target_link_libraries(gvm-agent ws2_32 rpcrt4)
    set_target_properties(gvm-agent PROPERTIES
        OUTPUT_NAME "gvm-agent"
        SUFFIX ".exe"
    )
elseif(UNIX AND NOT APPLE)
    # Linux-specific settings per Section 7.2.5 + uuid for Phase 2
    target_link_libraries(gvm-agent m uuid)
elseif(APPLE)
    # macOS-specific settings per Section 7.2.5
    target_link_libraries(gvm-agent m)
endif()

# Installation rules
install(TARGETS gvm-agent
    RUNTIME DESTINATION bin
)

# Install configuration template
install(FILES config/agent.conf.template
    DESTINATION etc/gvm-agent
    RENAME agent.conf
)

# CPack configuration for packaging
set(CPACK_PACKAGE_NAME "gvm-agent")
set(CPACK_PACKAGE_VERSION "${AGENT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "GVM Agent for Vulnerability Scanning")
set(CPACK_PACKAGE_VENDOR "Greenbone")
set(CPACK_PACKAGE_CONTACT "support@greenbone.net")

if(WIN32)
    # Windows installer per Section 7.2.5
    set(CPACK_GENERATOR "NSIS;ZIP")
    set(CPACK_NSIS_DISPLAY_NAME "GVM Agent ${AGENT_VERSION}")
    set(CPACK_NSIS_PACKAGE_NAME "GVM Agent")
elseif(UNIX AND NOT APPLE)
    # Linux packages per Section 7.2.5 (Phase 2: added SQLite3, uuid)
    set(CPACK_GENERATOR "DEB;RPM")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libcurl4, libc6, libsqlite3-0, uuid-runtime, rsync")
    set(CPACK_RPM_PACKAGE_REQUIRES "libcurl >= 7.29.0, sqlite >= 3.7, util-linux, rsync")
elseif(APPLE)
    # macOS package per Section 7.2.5
    set(CPACK_GENERATOR "productbuild")
endif()

include(CPack)

# Build summary
message(STATUS "GVM Agent Configuration")
message(STATUS "  Version: ${AGENT_VERSION}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  Install Prefix: ${CMAKE_INSTALL_PREFIX}")
