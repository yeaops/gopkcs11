# p11tool

p11tool is a command-line tool for PKCS#11 cryptographic operations using gopkcs11. It supports key pair generation, import, export, signing, decryption and other operations.

## Features

- **Key Generation**: Support for RSA, ECDSA and ED25519 key pair generation
- **Key Import**: Import PEM/DER format private keys to PKCS#11 devices
- **Key Export**: Export public keys in PEM/DER format
- **Digital Signature**: Digital signing using private keys in PKCS#11 devices
- **Data Decryption**: Decrypt data using RSA private keys
- **Key Management**: List, view and delete keys in PKCS#11 devices
- **Multiple Configuration Methods**: Support for command-line parameters and environment variables

## Build

```bash
# Build binary
make build

# Clean build files
make clean

# Install to system path
make install
```

## Usage

### Basic Syntax

```bash
p11tool <command> [options]
```

### Global Options

- `--lib`: PKCS#11 library path (default: `/usr/lib/softhsm/libsofthsm2.so`)
- `--slot`: PKCS#11 slot number (default: `0`)
- `--pin`: User PIN (default: `1234`)

### Environment Variables

You can set default values through environment variables:

- `PKCS11_LIB`: Set default PKCS#11 library path
- `PKCS11_SLOT`: Set default slot number
- `PKCS11_PIN`: Set default PIN

## Command Details

### 1. Generate Key Pairs (generate)

#### RSA Key Pairs

```bash
# Generate 2048-bit RSA key pair
p11tool generate --type rsa --size 2048 --label mykey

# Generate 4096-bit RSA key pair
p11tool generate --type rsa --size 4096 --label mykey-rsa4096
```

#### ECDSA Key Pairs

```bash
# Generate P-256 curve ECDSA key pair
p11tool generate --type ecdsa --curve p256 --label mykey-ecdsa

# Generate P-384 curve ECDSA key pair
p11tool generate --type ecdsa --curve p384 --label mykey-ecdsa384
```

#### ED25519 Key Pairs

```bash
# Generate ED25519 key pair
p11tool generate --type ed25519 --label mykey-ed25519
```

### 2. List Keys (list)

```bash
# List all keys
p11tool list

# Use custom configuration
p11tool list --lib /path/to/libpkcs11.so --slot 1 --pin 5678
```

### 3. Import Private Keys (import)

```bash
# Import RSA private key
p11tool import --file private_rsa.pem --label imported-rsa

# Import ECDSA private key
p11tool import --file private_ecdsa.pem --label imported-ecdsa

# Import ED25519 private key
p11tool import --file private_ed25519.pem --label imported-ed25519
```

Supported private key formats:
- PKCS#1 RSA private key (`-----BEGIN RSA PRIVATE KEY-----`)
- PKCS#8 private key (`-----BEGIN PRIVATE KEY-----`)
- SEC1 EC private key (`-----BEGIN EC PRIVATE KEY-----`)

### 4. Export Public Keys (export)

```bash
# Export as PEM format to stdout
p11tool export --label mykey --format pem

# Export as PEM format to file
p11tool export --label mykey --format pem --output public.pem

# Export as DER format
p11tool export --label mykey --format der --output public.der
```

### 5. Digital Signature (sign)

```bash
# Sign string data
p11tool sign --label mykey --data "hello world"

# Sign file data
p11tool sign --label mykey --file data.txt

# Save signature to file
p11tool sign --label mykey --data "hello world" --output signature.bin
```

### 6. Data Decryption (decrypt)

```bash
# Decrypt file (RSA keys only)
p11tool decrypt --label rsa-key --file encrypted.bin

# Decrypt and save to file
p11tool decrypt --label rsa-key --file encrypted.bin --output decrypted.txt
```

### 7. View Key Information (info)

```bash
# Show detailed key information
p11tool info --label mykey
```

Example output:

```
Key Information:
  Label: mykey
  Type: RSA
  Size: 2048 bits
  ID: a1b2c3d4e5f6789a
  Modulus size: 2048 bits
  Public exponent: 65537
```

### 8. Delete Keys (delete)

```bash
# Delete key (requires confirmation)
p11tool delete --label mykey

# Force delete (no confirmation)
p11tool delete --label mykey --force
```

**Note**: Delete functionality is not yet implemented in the gopkcs11 library.

## Configuration Examples

### Using Environment Variables

```bash
export PKCS11_LIB="/usr/local/lib/libpkcs11.so"
export PKCS11_SLOT="2"
export PKCS11_PIN="123456"

# Use environment variable configuration
p11tool list
```

### Using Command Line Parameters

```bash
# Explicitly specify configuration
p11tool generate \
  --type rsa \
  --size 2048 \
  --label mykey \
  --lib /usr/local/lib/libpkcs11.so \
  --slot 2 \
  --pin 123456
```

## Security Notes

1. **PIN Security**: Avoid entering PIN directly in command line, recommend using environment variables
2. **Private Key Protection**: Imported private keys are marked as sensitive and non-extractable in PKCS#11 devices
3. **Permission Management**: Ensure only authorized users can access PKCS#11 devices and related files

## Troubleshooting

### Common Errors

1. **Library file not found**

   ```
   Error: failed to create PKCS#11 client: failed to initialize PKCS#11
   ```
   
   Solution: Check if the library file path specified by `--lib` parameter is correct

2. **Slot does not exist**

   ```
   Error: failed to open session on slot ID X
   ```
   
   Solution: Use correct slot number or check available slots

3. **Wrong PIN**

   ```
   Error: failed to login as CKU_USER
   ```
   
   Solution: Confirm PIN is correct

4. **Key not found**

   ```
   Error finding key: key not found
   ```
   
   Solution: Check if key label is correct, use `list` command to view available keys

## Compatibility

- **Go Version**: 1.24.4+
- **PKCS#11 Standard**: 2.40
- **Supported HSMs**: SoftHSM, Utimaco, Thales, SafeNet, etc.
- **Operating Systems**: Linux, macOS, Windows

## License

This project uses the same license as gopkcs11.