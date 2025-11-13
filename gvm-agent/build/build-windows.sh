#!/bin/bash
# Build script for Windows GVM Agent
# Per PRD Section 7.2.5 - Windows packaging (.exe, .msi)
#
# Requirements:
# - MinGW-w64 cross-compiler
# - CMake 3.10+
# - WiX Toolset (for MSI)
# - libcurl development libraries

set -e

echo "=================================================="
echo "Building GVM Agent for Windows"
echo "=================================================="

# Configuration
BUILD_DIR="build/windows"
INSTALL_DIR="install/windows"
VERSION="1.0.0"

# Clean previous build
rm -rf "$BUILD_DIR" "$INSTALL_DIR"
mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

# Cross-compile for Windows using MinGW
echo "Configuring CMake for Windows..."
cd "$BUILD_DIR"

cmake ../.. \
    -DCMAKE_TOOLCHAIN_FILE=../../cmake/Toolchain-mingw-w64-x86_64.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
    -DBUILD_WINDOWS=ON

# Build
echo "Building agent..."
cmake --build . --config Release

# Install
echo "Installing to $INSTALL_DIR..."
cmake --install .

# Create ZIP package
echo "Creating ZIP package..."
cd "$INSTALL_DIR"
zip -r "../../gvm-agent-${VERSION}-windows-x64.zip" .

echo "=================================================="
echo "Build complete!"
echo "Package: gvm-agent-${VERSION}-windows-x64.zip"
echo "=================================================="

# Note: MSI creation requires WiX Toolset on Windows
# For cross-compilation, use NSIS or create MSI on Windows build machine
