#!/bin/bash

# p11tool test example script
# Note: Requires SoftHSM or other PKCS#11 device to be configured first

echo "=== p11tool Test Example ==="

# Set environment variables (modify according to actual situation)
export PKCS11_LIB="/usr/local/lib/softhsm/libsofthsm2.so"
export PKCS11_SLOT="0"
export PKCS11_PIN="1234"

echo "1. Show version information"
./p11tool version
echo

echo "2. Try to list existing keys"
./p11tool list 2>/dev/null || echo "   Note: Need to configure PKCS#11 device (like SoftHSM) first"
echo

echo "3. Show help information"
./p11tool help | head -10
echo "   ... (more help information omitted)"
echo

echo "=== Basic functionality verification completed ==="
echo "For complete testing, please configure PKCS#11 device first, then run:"
echo "  ./p11tool generate --type rsa --size 2048 --label test-key"
echo "  ./p11tool list"
echo "  ./p11tool info --label test-key"