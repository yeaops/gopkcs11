package gopkcs11

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"io"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// RSAKeyPair wraps a KeyPair and implements both crypto.Signer and crypto.Decrypter
// interfaces for RSA keys. It provides all RSA operations (signing and decryption)
// in a single type.
type RSAKeyPair struct {
	*KeyPair
}

// NewRSAKeyPair creates a new RSAKeyPair from a KeyPair.
// Returns an error if the KeyPair is not an RSA key.
func NewRSAKeyPair(keyPair *KeyPair) (*RSAKeyPair, error) {
	if keyPair.KeyType != KeyPairTypeRSA {
		return nil, errors.New("key pair must be an RSA key")
	}

	return &RSAKeyPair{
		KeyPair: keyPair,
	}, nil
}

// Public returns the public key corresponding to the private key.
func (r *RSAKeyPair) Public() crypto.PublicKey {
	return r.KeyPair.PublicKey
}

// Sign implements crypto.Signer interface for RSA keys.
// Supports PKCS#1 v1.5 and PSS padding schemes based on the opts parameter.
func (r *RSAKeyPair) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Check if this is PSS signing
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		return r.signPSS(digest, pssOpts)
	}

	// Default to PKCS#1 v1.5 signing
	return r.signPKCS1v15(digest, opts.HashFunc())
}

// Decrypt implements crypto.Decrypter interface for RSA keys.
// Supports PKCS#1 v1.5 and OAEP padding schemes based on the opts parameter.
// If opts is nil, PKCS#1 v1.5 padding is used by default.
func (r *RSAKeyPair) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	session, err := r.client.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	mechanism, err := r.getRSADecryptMechanism(opts)
	if err != nil {
		return nil, err
	}

	if err := r.client.ctx.DecryptInit(session, []*pkcs11.Mechanism{mechanism}, r.Handle); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	plaintext, err := r.client.ctx.Decrypt(session, ciphertext)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return plaintext, nil
}

// digestInfo contains the ASN.1 structure for PKCS#1 v1.5 DigestInfo
type digestInfo struct {
	Algorithm algorithmIdentifier
	Digest    []byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// Hash algorithm OIDs for DigestInfo construction
var (
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// buildDigestInfo constructs the DigestInfo structure for PKCS#1 v1.5 signing
func buildDigestInfo(hash crypto.Hash, digest []byte) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	switch hash {
	case crypto.SHA1:
		oid = oidSHA1
	case crypto.SHA224:
		oid = oidSHA224
	case crypto.SHA256:
		oid = oidSHA256
	case crypto.SHA384:
		oid = oidSHA384
	case crypto.SHA512:
		oid = oidSHA512
	default:
		return nil, errors.New("unsupported hash function")
	}

	digInfo := digestInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.RawValue{Tag: 5}, // NULL
		},
		Digest: digest,
	}

	return asn1.Marshal(digInfo)
}

// signPKCS1v15 performs RSA signing with PKCS#1 v1.5 padding
func (r *RSAKeyPair) signPKCS1v15(digest []byte, hash crypto.Hash) ([]byte, error) {
	// Validate digest length
	var expectedLen int
	switch hash {
	case crypto.SHA1:
		expectedLen = 20
	case crypto.SHA224:
		expectedLen = 28
	case crypto.SHA256:
		expectedLen = 32
	case crypto.SHA384:
		expectedLen = 48
	case crypto.SHA512:
		expectedLen = 64
	default:
		return nil, errors.New("unsupported hash function for PKCS#1 v1.5")
	}

	if len(digest) != expectedLen {
		return nil, errors.Errorf("digest length mismatch: expected %d, got %d", expectedLen, len(digest))
	}

	// Build DigestInfo structure
	digestInfo, err := buildDigestInfo(hash, digest)
	if err != nil {
		return nil, err
	}

	session, err := r.client.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Use CKM_RSA_PKCS with DigestInfo
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)

	if err := r.client.ctx.SignInit(session, []*pkcs11.Mechanism{mechanism}, r.Handle); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	signature, err := r.client.ctx.Sign(session, digestInfo)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return signature, nil
}

// signPSS performs RSA signing with PSS padding
func (r *RSAKeyPair) signPSS(digest []byte, opts *rsa.PSSOptions) ([]byte, error) {
	// Validate digest length and get PSS parameters
	var expectedLen int
	var hashAlg, mgf uint

	switch opts.Hash {
	case crypto.SHA1:
		expectedLen = 20
		hashAlg = pkcs11.CKM_SHA_1
		mgf = pkcs11.CKG_MGF1_SHA1
	case crypto.SHA224:
		expectedLen = 28
		hashAlg = pkcs11.CKM_SHA224
		mgf = pkcs11.CKG_MGF1_SHA224
	case crypto.SHA256:
		expectedLen = 32
		hashAlg = pkcs11.CKM_SHA256
		mgf = pkcs11.CKG_MGF1_SHA256
	case crypto.SHA384:
		expectedLen = 48
		hashAlg = pkcs11.CKM_SHA384
		mgf = pkcs11.CKG_MGF1_SHA384
	case crypto.SHA512:
		expectedLen = 64
		hashAlg = pkcs11.CKM_SHA512
		mgf = pkcs11.CKG_MGF1_SHA512
	default:
		return nil, errors.New("unsupported hash function for RSA-PSS")
	}

	if len(digest) != expectedLen {
		return nil, errors.Errorf("digest length mismatch: expected %d, got %d", expectedLen, len(digest))
	}

	// Determine salt length
	saltLen := expectedLen // Default to hash length
	if opts.SaltLength == rsa.PSSSaltLengthAuto || opts.SaltLength == rsa.PSSSaltLengthEqualsHash {
		saltLen = expectedLen
	} else if opts.SaltLength >= 0 {
		saltLen = opts.SaltLength
	}

	session, err := r.client.GetSession()
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	// Set up PSS parameters
	pssParams := pkcs11.NewPSSParams(hashAlg, mgf, uint(saltLen))

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, pssParams)

	if err := r.client.ctx.SignInit(session, []*pkcs11.Mechanism{mechanism}, r.Handle); err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	signature, err := r.client.ctx.Sign(session, digest)
	if err != nil {
		return nil, ConvertPKCS11Error(err)
	}

	return signature, nil
}

// getRSADecryptMechanism determines the appropriate PKCS#11 mechanism for RSA decryption
// based on the decryption options.
func (r *RSAKeyPair) getRSADecryptMechanism(opts crypto.DecrypterOpts) (*pkcs11.Mechanism, error) {
	if opts == nil {
		return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), nil
	}

	switch opt := opts.(type) {
	case *rsa.PKCS1v15DecryptOptions:
		return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), nil
	case *rsa.OAEPOptions:
		var mechanismType uint
		switch opt.Hash {
		case crypto.SHA1:
			mechanismType = pkcs11.CKM_RSA_PKCS_OAEP
		case crypto.SHA256:
			mechanismType = pkcs11.CKM_RSA_PKCS_OAEP
		default:
			return nil, errors.New("unsupported hash function for RSA-OAEP")
		}

		var oaepParams *pkcs11.OAEPParams
		switch opt.Hash {
		case crypto.SHA1:
			oaepParams = &pkcs11.OAEPParams{
				HashAlg:    pkcs11.CKM_SHA_1,
				MGF:        pkcs11.CKG_MGF1_SHA1,
				SourceType: pkcs11.CKZ_DATA_SPECIFIED,
				SourceData: nil,
			}
		case crypto.SHA256:
			oaepParams = &pkcs11.OAEPParams{
				HashAlg:    pkcs11.CKM_SHA256,
				MGF:        pkcs11.CKG_MGF1_SHA256,
				SourceType: pkcs11.CKZ_DATA_SPECIFIED,
				SourceData: nil,
			}
		}

		if len(opt.Label) > 0 {
			oaepParams.SourceData = opt.Label
		}

		return pkcs11.NewMechanism(mechanismType, oaepParams), nil
	default:
		return nil, errors.New("unsupported decryption options")
	}
}

// SignPKCS1v15 provides a convenient method for RSA signing with PKCS#1 v1.5 padding.
func (r *RSAKeyPair) SignPKCS1v15(hash crypto.Hash, digest []byte) ([]byte, error) {
	return r.Sign(rand.Reader, digest, hash)
}

// SignPSS provides a convenient method for RSA signing with PSS padding.
func (r *RSAKeyPair) SignPSS(hash crypto.Hash, digest []byte) ([]byte, error) {
	opts := &rsa.PSSOptions{
		Hash: hash,
	}
	return r.Sign(rand.Reader, digest, opts)
}

// DecryptPKCS1v15 provides a convenient method for RSA decryption with PKCS#1 v1.5 padding.
func (r *RSAKeyPair) DecryptPKCS1v15(ciphertext []byte) ([]byte, error) {
	opts := &rsa.PKCS1v15DecryptOptions{}
	return r.Decrypt(rand.Reader, ciphertext, opts)
}

// DecryptOAEP provides a convenient method for RSA decryption with OAEP padding.
func (r *RSAKeyPair) DecryptOAEP(hash crypto.Hash, ciphertext []byte, label []byte) ([]byte, error) {
	opts := &rsa.OAEPOptions{
		Hash:  hash,
		Label: label,
	}
	return r.Decrypt(rand.Reader, ciphertext, opts)
}
