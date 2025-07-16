# gopkcs11

A Go wrapper for PKCS#11 (Cryptoki) operations with HSM (Hardware Security Module) support.

## Installation

```bash
go get github.com/yeaops/gopkcs11
```

## Configuration Options

### Slot Identification Methods

```go
// By Slot ID (most common)
config := gopkcs11.NewConfigWithSlotID("/path/to/lib.so", 0, "pin")

// By Slot Index
config := gopkcs11.NewConfigWithSlotIndex("/path/to/lib.so", 0, "pin")

// By Token Label
config := gopkcs11.NewConfigWithTokenLabel("/path/to/lib.so", "MyToken", "pin")

// By Token Serial Number
config := gopkcs11.NewConfigWithTokenSerial("/path/to/lib.so", "123456", "pin")
```

### Environment Variables

| Variable              | Description                 | Default                     |
| --------------------- | --------------------------- | --------------------------- |
| `PKCS11_LIBRARY_PATH` | Path to PKCS#11 library     | Auto-detect bundled SoftHSM |
| `PKCS11_USER_PIN`     | User PIN for authentication | Required                    |
| `PKCS11_SLOT_ID`      | Slot ID to use              | -                           |
| `PKCS11_SLOT_INDEX`   | Slot index to use           | -                           |
| `PKCS11_TOKEN_LABEL`  | Token label to use          | -                           |
| `PKCS11_TOKEN_SERIAL` | Token serial number to use  | -                           |

## Error Handling

```go
if gopkcs11.IsKeyNotFoundError(err) {
    // Handle key not found
}
if gopkcs11.IsAuthenticationError(err) {
    // Handle authentication failure
}
if gopkcs11.IsSessionError(err) {
    // Handle session-related errors
}
```

## Security Considerations

- Private keys are marked as non-extractable and sensitive
- All cryptographic operations are performed within the HSM
- Session management includes proper cleanup and logout procedures
- Error messages avoid leaking sensitive information

## Testing

```bash
go test ./...
```

## License

This project is licensed under the MIT License.
