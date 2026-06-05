package gopkcs11

import (
	"context"

	"github.com/pkg/errors"
)

// GenerateRandom generates random bytes using the HSM's hardware random number generator.
// This is equivalent to the pkcs11-tool command:
//
//	pkcs11-tool --module ./cs_pkcs11_R3.so --generate-random <length> --slot <slot> --pin <pin>
//
// The length parameter specifies the number of random bytes to generate.
// This method uses the HSM's built-in cryptographic random number generator,
// which provides high-quality entropy suitable for cryptographic operations.
//
// Example usage:
//
//	token, _ := gopkcs11.NewToken(config)
//	defer token.Close()
//
//	// Generate 32 random bytes (256 bits)
//	randomBytes, err := token.GenerateRandom(context.Background(), 32)
//	if err != nil {
//	    log.Fatalf("Failed to generate random bytes: %v", err)
//	}
//	fmt.Printf("Generated %d random bytes: %x\n", len(randomBytes), randomBytes)
func (t *Token) GenerateRandom(ctx context.Context, length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("length must be positive")
	}

	session, err := t.GetSession(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to acquire session")
	}
	defer session.Release()

	randomBytes, err := session.GetCtx().GenerateRandom(session.GetHandle(), length)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate random bytes from HSM")
	}

	return randomBytes, nil
}
