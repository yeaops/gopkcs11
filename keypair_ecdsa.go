package gopkcs11

import (
	"crypto"
	"io"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// ECDSAKeyPair wraps a KeyPair and implements the crypto.Signer interface
// for ECDSA keys. Note that ECDSA keys do not support encryption/decryption operations.
type ECDSAKeyPair struct {
	*KeyPair
}

// NewECDSAKeyPair creates a new ECDSAKeyPair from a KeyPair.
// Returns an error if the KeyPair is not an ECDSA key.
func NewECDSAKeyPair(keyPair *KeyPair) (*ECDSAKeyPair, error) {
	if keyPair.KeyType != KeyPairTypeECDSA {
		return nil, errors.New("key pair must be an ECDSA key")
	}

	return &ECDSAKeyPair{
		KeyPair: keyPair,
	}, nil
}

// Public returns the public key corresponding to the private key.
func (e *ECDSAKeyPair) Public() crypto.PublicKey {
	return e.KeyPair.Public()
}

// Sign implements crypto.Signer interface for ECDSA keys.
// The digest parameter should be the already-hashed data.
// ECDSA signatures are converted to DER format for compatibility with Go's crypto interfaces.
func (e *ECDSAKeyPair) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	session, err := e.client.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	mechanism, expectedDigestLen, err := e.getECDSASignMechanism(opts)
	if err != nil {
		return nil, err
	}

	if len(digest) != expectedDigestLen {
		return nil, errors.Errorf("digest length mismatch: expected %d, got %d", expectedDigestLen, len(digest))
	}

	if err := e.client.ctx.SignInit(session, []*pkcs11.Mechanism{mechanism}, e.Handle); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	signature, err := e.client.ctx.Sign(session, digest)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Convert ECDSA signature from raw format (r||s) to DER encoding
	signature, err = e.convertECDSASignatureToDER(signature)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert ECDSA signature to DER format")
	}

	return signature, nil
}

// getECDSASignMechanism determines the appropriate PKCS#11 mechanism for ECDSA signing
// and validates the hash function. ECDSA uses CKM_ECDSA mechanism for all hash types.
func (e *ECDSAKeyPair) getECDSASignMechanism(opts crypto.SignerOpts) (*pkcs11.Mechanism, int, error) {
	var expectedDigestLen int

	switch opts.HashFunc() {
	case crypto.SHA1:
		expectedDigestLen = 20
	case crypto.SHA224:
		expectedDigestLen = 28
	case crypto.SHA256:
		expectedDigestLen = 32
	case crypto.SHA384:
		expectedDigestLen = 48
	case crypto.SHA512:
		expectedDigestLen = 64
	default:
		return nil, 0, errors.New("unsupported hash function for ECDSA")
	}

	return pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), expectedDigestLen, nil
}

// convertECDSASignatureToDER converts an ECDSA signature from the raw format
// returned by PKCS#11 (r||s) to DER encoding as expected by Go's crypto interfaces.
func (e *ECDSAKeyPair) convertECDSASignatureToDER(signature []byte) ([]byte, error) {
	if len(signature)%2 != 0 {
		return nil, errors.New("invalid ECDSA signature length")
	}

	halfLen := len(signature) / 2
	r := new(big.Int).SetBytes(signature[:halfLen])
	s := new(big.Int).SetBytes(signature[halfLen:])

	rBytes := r.Bytes()
	sBytes := s.Bytes()

	if len(rBytes) == 0 || len(sBytes) == 0 {
		return nil, errors.New("invalid ECDSA signature components")
	}

	rLen := len(rBytes)
	sLen := len(sBytes)

	if rBytes[0] >= 0x80 {
		rLen++
	}
	if sBytes[0] >= 0x80 {
		sLen++
	}

	totalLen := 4 + rLen + sLen
	if totalLen >= 0x80 {
		totalLen++
	}

	der := make([]byte, 0, totalLen+2)
	der = append(der, 0x30)

	if totalLen-2 >= 0x80 {
		der = append(der, 0x81, byte(totalLen-3))
	} else {
		der = append(der, byte(totalLen-2))
	}

	der = append(der, 0x02)
	if rBytes[0] >= 0x80 {
		der = append(der, byte(len(rBytes)+1), 0x00)
	} else {
		der = append(der, byte(len(rBytes)))
	}
	der = append(der, rBytes...)

	der = append(der, 0x02)
	if sBytes[0] >= 0x80 {
		der = append(der, byte(len(sBytes)+1), 0x00)
	} else {
		der = append(der, byte(len(sBytes)))
	}
	der = append(der, sBytes...)

	return der, nil
}

// SignHash provides a convenient method for ECDSA signing with a specific hash function.
// It expects the digest to be already computed with the specified hash function.
func (e *ECDSAKeyPair) SignHash(hash crypto.Hash, digest []byte) ([]byte, error) {
	return e.Sign(nil, digest, hash)
}
