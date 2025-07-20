#!/bin/bash

# Utimaco CryptoServer Test Setup Script
# This script helps configure environment variables and checks for Utimaco components

set -e

echo "=== Utimaco CryptoServer Test Setup ==="

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if file exists
file_exists() {
    [ -f "$1" ]
}

# Check for Utimaco PKCS#11 library
echo "Checking for Utimaco PKCS#11 library..."

UTIMACO_LIBRARY_PATHS=(
    "/usr/lib/libcs_pkcs11_R3.so"
    "/opt/utimaco/lib/libcs_pkcs11_R3.so"
    "/usr/local/lib/libcs_pkcs11_R3.so"
    "/usr/lib64/libcs_pkcs11_R3.so"
)

FOUND_LIBRARY=""
for path in "${UTIMACO_LIBRARY_PATHS[@]}"; do
    if file_exists "$path"; then
        FOUND_LIBRARY="$path"
        echo "Found Utimaco PKCS#11 library at: $path"
        break
    fi
done

if [ -z "$FOUND_LIBRARY" ]; then
    echo "WARNING: Utimaco PKCS#11 library not found in standard locations."
    echo "Please ensure the Utimaco CryptoServer PKCS#11 library is installed."
    echo "You can set PKCS11_LIBRARY_PATH environment variable to specify the library path."
    echo ""
    echo "Standard installation paths:"
    for path in "${UTIMACO_LIBRARY_PATHS[@]}"; do
        echo "  - $path"
    done
else
    echo "export PKCS11_LIBRARY_PATH=\"$FOUND_LIBRARY\""
fi

echo ""

# Environment variables configuration
echo "=== Environment Variables ==="
echo "The following environment variables can be configured for Utimaco testing:"
echo ""

echo "# Required: Path to Utimaco PKCS#11 library"
if [ -n "$FOUND_LIBRARY" ]; then
    echo "export PKCS11_LIBRARY_PATH=\"$FOUND_LIBRARY\""
else
    echo "export PKCS11_LIBRARY_PATH=\"/path/to/libcs_pkcs11_R3.so\""
fi

echo ""
echo "# Optional: Utimaco device specification"
echo "# For simulator: export UTIMACO_DEVICE=\"3001@127.0.0.1\""
echo "# For local device: export UTIMACO_DEVICE=\"/dev/cs2.0\""
echo "# For remote device: export UTIMACO_DEVICE=\"192.168.1.100\""
echo "export UTIMACO_DEVICE=\"3001@127.0.0.1\"  # Default simulator"

echo ""
echo "# Optional: User PIN for authentication"
echo "export UTIMACO_USER_PIN=\"12345678\"  # Default PIN"

echo ""
echo "# Optional: Slot ID (auto-detected if not specified)"
echo "# export UTIMACO_SLOT_ID=\"0\""

echo ""

# Check for Utimaco tools
echo "=== Utimaco Tools Check ==="
UTIMACO_TOOLS=(
    "csadm"
    "cscfg"
    "csstat"
    "p11tool2"
)

for tool in "${UTIMACO_TOOLS[@]}"; do
    if command_exists "$tool"; then
        echo "✓ $tool found"
    else
        echo "✗ $tool not found (optional)"
    fi
done

echo ""

# Configuration file template
echo "=== Configuration Template ==="
echo "A configuration file template is available at:"
echo "  utimaco-cs_pkcs11_R3.cfg.tmpl"
echo ""
echo "The CS_PKCS11_R3_CFG environment variable will be automatically set"
echo "to point to a generated configuration file during testing."

echo ""

# Usage instructions
echo "=== Usage Instructions ==="
echo "1. Set the required environment variables:"
echo "   export PKCS11_LIBRARY_PATH=\"/path/to/libcs_pkcs11_R3.so\""
echo "   export UTIMACO_DEVICE=\"your_device_specification\""
echo "   export UTIMACO_USER_PIN=\"your_pin\""
echo ""
echo "2. Run the tests:"
echo "   cd test/e2e/utimaco"
echo "   go test -v ./..."
echo ""
echo "3. For specific tests:"
echo "   go test -run TestUtimaco -v"
echo "   go test -run TestUtimacoToken -v"
echo "   go test -run TestUtimacoKeypair -v"

echo ""
echo "=== Setup Complete ==="