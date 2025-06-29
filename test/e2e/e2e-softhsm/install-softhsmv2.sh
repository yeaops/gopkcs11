#!/bin/bash

# SoftHSMv2 Cross-Platform Build Script
# This script compiles SoftHSMv2 from source and installs it to ./build directory

set -e

# Configuration
SOFTHSM_VERSION="2.6.1"
SOFTHSM_URL="https://github.com/softhsm/SoftHSMv2/archive/refs/tags/${SOFTHSM_VERSION}.tar.gz"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
TEMP_DIR="${SCRIPT_DIR}/temp_build"
SOURCE_DIR="${TEMP_DIR}/softhsm-${SOFTHSM_VERSION}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect platform
detect_platform() {
    case "$(uname -s)" in
        Linux*)     PLATFORM=Linux;;
        Darwin*)    PLATFORM=Mac;;
        CYGWIN*|MINGW*|MSYS*) PLATFORM=Windows;;
        *)          PLATFORM="UNKNOWN";;
    esac
    log_info "Detected platform: $PLATFORM"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."

    local missing_deps=()

    # Common dependencies
    command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1 || missing_deps+=("gcc/clang")
    command -v make >/dev/null 2>&1 || missing_deps+=("make")
    command -v autoconf >/dev/null 2>&1 || missing_deps+=("autoconf")
    command -v automake >/dev/null 2>&1 || missing_deps+=("automake")
    command -v libtool >/dev/null 2>&1 || missing_deps+=("libtool")
    command -v pkg-config >/dev/null 2>&1 || missing_deps+=("pkg-config")

    # Platform-specific checks
    case $PLATFORM in
        Linux)
            # Check for OpenSSL development headers
            if ! pkg-config --exists openssl; then
                missing_deps+=("libssl-dev/openssl-devel")
            fi
            ;;
        Mac)
            # Check for Homebrew OpenSSL
            if ! brew --prefix openssl >/dev/null 2>&1; then
                missing_deps+=("openssl (via Homebrew)")
            fi
            ;;
        Windows)
            log_warning "Windows build requires MSYS2/MinGW environment"
            ;;
    esac

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        show_install_instructions
        exit 1
    fi

    log_success "All dependencies are available"
}

# Show installation instructions for dependencies
show_install_instructions() {
    log_info "Installation instructions:"
    case $PLATFORM in
        Linux)
            echo "Ubuntu/Debian:"
            echo "  sudo apt-get update"
            echo "  sudo apt-get install build-essential autoconf automake libtool-bin pkg-config libssl-dev"
            echo ""
            echo "CentOS/RHEL/Fedora:"
            echo "  sudo yum install gcc gcc-c++ make autoconf automake libtool pkgconfig openssl-devel"
            echo "  # or for newer versions:"
            echo "  sudo dnf install gcc gcc-c++ make autoconf automake libtool pkgconfig openssl-devel"
            ;;
        Mac)
            echo "macOS (using Homebrew):"
            echo "  brew install autoconf automake libtool pkg-config openssl"
            ;;
        Windows)
            echo "Windows (MSYS2):"
            echo "  pacman -S base-devel mingw-w64-x86_64-toolchain"
            echo "  pacman -S mingw-w64-x86_64-autotools mingw-w64-x86_64-openssl"
            ;;
    esac
}

# Download and extract source
download_source() {
    log_info "Downloading SoftHSMv2 source..."

    # Create temp directory
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"

    # Try downloading
    local download_success=false
    local filename="softhsm-${SOFTHSM_VERSION}.tar.gz"

    if command -v wget >/dev/null 2>&1; then
        if wget "$SOFTHSM_URL" -O "$filename" 2>/dev/null; then
            download_success=true
        fi
    elif command -v curl >/dev/null 2>&1; then
        if curl -L "$SOFTHSM_URL" -o "$filename" 2>/dev/null; then
            download_success=true
        fi
    fi

    if [ "$download_success" = false ]; then
        log_error "Failed to download from sources"
        log_error "Source: $SOFTHSM_URL"
        exit 1
    fi

    # Extract
    log_info "Extracting source..."
    tar -xzf "$filename"

    # Handle different directory structures (GitHub vs official release)
    if [ -d "softhsm-${SOFTHSM_VERSION}" ]; then
        SOURCE_DIR="${TEMP_DIR}/softhsm-${SOFTHSM_VERSION}"
    elif [ -d "SoftHSMv2-${SOFTHSM_VERSION}" ]; then
        SOURCE_DIR="${TEMP_DIR}/SoftHSMv2-${SOFTHSM_VERSION}"
    else
        log_error "Could not find extracted source directory"
        exit 1
    fi

    log_success "Source downloaded and extracted to: $SOURCE_DIR"
}

# Configure build
configure_build() {
    log_info "Configuring build..."

    cd "$SOURCE_DIR"

    # Check if we need to run autogen.sh (for GitHub source)
    if [ ! -f "configure" ] && [ -f "autogen.sh" ]; then
        log_info "Running autogen.sh to generate configure script..."
        ./autogen.sh
    fi

    # Verify configure script exists
    if [ ! -f "configure" ]; then
        log_error "Configure script not found after autogen"
        exit 1
    fi

    # Platform-specific configuration
    local config_args="--prefix=$BUILD_DIR"
    config_args="$config_args --enable-ecc"
    config_args="$config_args --enable-eddsa"  

    case $PLATFORM in
        Mac)
            local openssl_prefix
            if brew --prefix openssl@3 >/dev/null 2>&1; then
                openssl_prefix=$(brew --prefix openssl@3)
            elif brew --prefix openssl >/dev/null 2>&1; then
                openssl_prefix=$(brew --prefix openssl)
            else
                openssl_prefix="/usr/local/opt/openssl"
            fi

            config_args="$config_args --with-openssl=$openssl_prefix"
            ;;
        Windows)
            # Windows-specific configuration
            config_args="$config_args --with-openssl=/mingw64"
            ;;
    esac

    log_info "Running configure with: $config_args"
    # shellcheck disable=SC2086
    ./configure $config_args

    log_success "Configuration completed"
}

# Build SoftHSMv2
build_softhsm() {
    log_info "Building SoftHSMv2..."

    cd "$SOURCE_DIR"

    # Determine number of CPU cores for parallel build
    local cores=1
    case $PLATFORM in
        Linux)
            cores=$(nproc 2>/dev/null || echo 1)
            ;;
        Mac)
            cores=$(sysctl -n hw.ncpu 2>/dev/null || echo 1)
            ;;
        Windows)
            cores=${NUMBER_OF_PROCESSORS:-1}
            ;;
    esac

    log_info "Building with $cores parallel jobs..."
    make -j"$cores"

    log_success "Build completed"
}

# Install SoftHSMv2
install_softhsm() {
    log_info "Installing SoftHSMv2 to $BUILD_DIR..."

    cd "$SOURCE_DIR"

    # Create build directory
    mkdir -p "$BUILD_DIR"

    # Install
    make install

    log_success "Installation completed"
}

# Create configuration and setup scripts
create_setup_scripts() {
    log_info "Creating setup scripts..."

    # Update existing configuration to use build directory structure
    cat > "$BUILD_DIR/softhsm2.conf" << EOF
# SoftHSM v2 configuration file

directories.tokendir = ${BUILD_DIR}/test_data/
objectstore.backend = file
log.level = INFO
slots.removable = false
EOF

    # Create test_data directory (keeping existing name from current config)
    mkdir -p "$BUILD_DIR/test_data"

    # Create setup script
    cat > "$BUILD_DIR/setup_env.sh" << 'EOF'
#!/bin/bash
# SoftHSMv2 Environment Setup Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export SOFTHSM2_CONF="$SCRIPT_DIR/softhsm2.conf"
export PATH="$SCRIPT_DIR/bin:$PATH"
export LD_LIBRARY_PATH="$SCRIPT_DIR/lib:$LD_LIBRARY_PATH"

echo "SoftHSMv2 environment configured"
echo "Configuration file: $SOFTHSM2_CONF"
echo "Binary path: $SCRIPT_DIR/bin"
echo "Token directory: $SCRIPT_DIR/test_data"
echo ""
echo "Usage:"
echo "  source $SCRIPT_DIR/setup_env.sh"
echo "  softhsm2-util --init-token --slot 0 --label test"
EOF

    chmod +x "$BUILD_DIR/setup_env.sh"

    # Create Windows batch file
    cat > "$BUILD_DIR/setup_env.bat" << 'EOF'
@echo off
set SCRIPT_DIR=%~dp0
for %%i in ("%SCRIPT_DIR%..") do set SCRIPT_DIR=%%~fi
set SOFTHSM2_CONF=%SCRIPT_DIR%\softhsm2.conf
set PATH=%SCRIPT_DIR%bin;%PATH%

echo SoftHSMv2 environment configured
echo Configuration file: %SOFTHSM2_CONF%
echo Binary path: %SCRIPT_DIR%bin
echo Token directory: %SCRIPT_DIR%\test_data
echo.
echo Usage:
echo   setup_env.bat
echo   softhsm2-util --init-token --slot 0 --label test
EOF

    log_success "Setup scripts created"
}

# Cleanup temporary files
cleanup() {
    log_info "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
    log_success "Cleanup completed"
}

# Main function
main() {
    log_info "Starting SoftHSMv2 build process..."

    detect_platform
    check_dependencies
    download_source
    configure_build
    build_softhsm
    install_softhsm
    create_setup_scripts
    cleanup

    log_success "SoftHSMv2 build and installation completed!"
    log_info "Installation directory: $BUILD_DIR"
    log_info "Configuration file: $BUILD_DIR/softhsm2.conf"
    log_info "To use SoftHSMv2, run: source $BUILD_DIR/setup_env.sh"
}

# Handle script interruption
trap cleanup EXIT

# Run main function
main "$@"