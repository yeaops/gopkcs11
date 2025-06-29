package gopkcs11

import (
	"crypto"
	"crypto/ed25519"
	"io"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// ED25519KeyPair wraps a KeyPair and implements the crypto.Signer interface
// for ED25519 keys. Note that ED25519 keys do not support encryption/decryption operations.
type ED25519KeyPair struct {
	*KeyPair
	client *Client
}

// NewED25519KeyPair creates a new ED25519KeyPair from a KeyPair.
// Returns an error if the KeyPair is not an ED25519 key.
func NewED25519KeyPair(client *Client, keyPair *KeyPair) (*ED25519KeyPair, error) {
	if keyPair.KeyType != KeyPairTypeED25519 {
		return nil, errors.New("key pair must be an ED25519 key")
	}

	return &ED25519KeyPair{
		KeyPair: keyPair,
		client:  client,
	}, nil
}

// Public returns the public key corresponding to the private key.
func (e *ED25519KeyPair) Public() crypto.PublicKey {
	return e.KeyPair.PublicKey
}

// Sign implements crypto.Signer interface for ED25519 keys.
// ED25519 signatures are deterministic and don't require a hash function.
// The message parameter should be the raw message data, not a pre-hashed digest.
func (e *ED25519KeyPair) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	// ED25519 is designed to sign the raw message, not a hash
	// If opts specifies a hash function, we should return an error
	if opts != nil && opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("ED25519 does not support pre-hashing; pass the raw message")
	}

	session, err := e.client.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// ED25519 uses CKM_EDDSA mechanism
	mechanism := pkcs11.NewMechanism(CKM_EDDSA, nil)

	if err := e.client.ctx.SignInit(session, []*pkcs11.Mechanism{mechanism}, e.Handle); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	signature, err := e.client.ctx.Sign(session, message)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// ED25519 signatures are 64 bytes
	if len(signature) != ed25519.SignatureSize {
		return nil, errors.Errorf("invalid ED25519 signature length: expected %d, got %d", ed25519.SignatureSize, len(signature))
	}

	return signature, nil
}

// SignMessage provides a convenient method for ED25519 signing.
// It expects the raw message data, not a pre-computed hash.
func (e *ED25519KeyPair) SignMessage(message []byte) ([]byte, error) {
	return e.Sign(nil, message, nil)
}