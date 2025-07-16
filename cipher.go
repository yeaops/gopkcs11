package gopkcs11

import (
	"context"
	"io"
)

// BlockCipher represents a block cipher that can be used for encryption and decryption.
// It provides methods for both in-place and streaming operations.
type BlockCipher interface {
	Encrypt(ctx context.Context, dst, src []byte) error
	Decrypt(ctx context.Context, dst, src []byte) error

	EncryptStream(ctx context.Context, dst io.Writer, src io.Reader) (int, error)
	DecryptStream(ctx context.Context, dst io.Writer, src io.Reader) (int, error)

	BlockSize() int
	KeySize() int
}
