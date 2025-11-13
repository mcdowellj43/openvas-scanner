# GVM Agent Makefile
# Quick build shortcuts

.PHONY: all build clean test install linux windows help

# Default target
all: build

# Build for current platform
build:
	@echo "Building GVM Agent..."
	@mkdir -p build
	@cd build && cmake .. && cmake --build .

# Build for Linux
linux:
	@echo "Building for Linux..."
	@./build/build-linux.sh

# Build for Windows (cross-compile)
windows:
	@echo "Building for Windows..."
	@./build/build-windows.sh

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf build install
	@rm -f *.deb *.rpm *.zip

# Install on current system
install: build
	@echo "Installing..."
	@cd build && sudo cmake --install .

# Run tests (Phase 2)
test:
	@echo "Tests not yet implemented (Phase 2)"

# Show help
help:
	@echo "GVM Agent Build System"
	@echo ""
	@echo "Targets:"
	@echo "  make build    - Build for current platform"
	@echo "  make linux    - Build Linux packages (.deb, .rpm)"
	@echo "  make windows  - Build Windows package (.zip)"
	@echo "  make install  - Install on current system"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make test     - Run tests (Phase 2)"
	@echo "  make help     - Show this help"
	@echo ""
	@echo "Per PRD Section 7.2 - Host-Based Agent"
