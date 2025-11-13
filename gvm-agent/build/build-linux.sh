#!/bin/bash
# Build script for Linux GVM Agent
# Per PRD Section 7.2.5 - Linux packaging (.deb, .rpm)
#
# Requirements:
# - GCC or Clang
# - CMake 3.10+
# - libcurl development libraries (libcurl4-openssl-dev)
# - uuid-dev

set -e

echo "=================================================="
echo "Building GVM Agent for Linux"
echo "=================================================="

# Configuration
BUILD_DIR="build/linux"
VERSION="1.0.0"

# Clean previous build
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Build
echo "Configuring CMake..."
cd "$BUILD_DIR"

cmake ../.. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_LINUX=ON

# Build
echo "Building agent..."
cmake --build . --config Release

# Create packages
echo "Creating packages..."

# DEB package
echo "Creating DEB package..."
cpack -G DEB

# RPM package
echo "Creating RPM package..."
cpack -G RPM

# List packages
echo ""
echo "=================================================="
echo "Build complete! Packages created:"
echo "=================================================="
ls -lh *.deb *.rpm

echo ""
echo "To install (Debian/Ubuntu):"
echo "  sudo dpkg -i gvm-agent-${VERSION}-Linux.deb"
echo ""
echo "To install (RHEL/CentOS):"
echo "  sudo rpm -i gvm-agent-${VERSION}-Linux.rpm"
echo "=================================================="
