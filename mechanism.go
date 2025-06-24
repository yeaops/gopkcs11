package gopkcs11

import (
	"encoding/binary"
)

// Mechanism represents a PKCS#11 mechanism
type Mechanism struct {
	Type      MechanismType
	Parameter []byte
}

// NewMechanism creates a new mechanism with the given type and parameter
func NewMechanism(mechanismType MechanismType, parameter []byte) *Mechanism {
	return &Mechanism{
		Type:      mechanismType,
		Parameter: parameter,
	}
}

// NewMechanismRSAPKCS creates an RSA PKCS mechanism
func NewMechanismRSAPKCS() *Mechanism {
	return NewMechanism(CKM_RSA_PKCS, nil)
}

// NewMechanismRSAPKCSKeyPairGen creates an RSA PKCS key pair generation mechanism
func NewMechanismRSAPKCSKeyPairGen() *Mechanism {
	return NewMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, nil)
}

// NewMechanismRSAWithHash creates an RSA mechanism with the given hash algorithm
func NewMechanismRSAWithHash(hashAlg MechanismType) *Mechanism {
	switch hashAlg {
	case CKM_SHA_1:
		return NewMechanism(CKM_SHA1_RSA_PKCS, nil)
	case CKM_SHA256:
		return NewMechanism(CKM_SHA256_RSA_PKCS, nil)
	case CKM_SHA384:
		return NewMechanism(CKM_SHA384_RSA_PKCS, nil)
	case CKM_SHA512:
		return NewMechanism(CKM_SHA512_RSA_PKCS, nil)
	default:
		return NewMechanism(CKM_RSA_PKCS, nil)
	}
}

// NewMechanismAESCBC creates an AES CBC mechanism with the given IV
func NewMechanismAESCBC(iv []byte) *Mechanism {
	return NewMechanism(CKM_AES_CBC, iv)
}

// NewMechanismAESCBCPad creates an AES CBC with padding mechanism with the given IV
func NewMechanismAESCBCPad(iv []byte) *Mechanism {
	return NewMechanism(CKM_AES_CBC_PAD, iv)
}

// NewMechanismAESGCM creates an AES GCM mechanism with the given parameters
func NewMechanismAESGCM(iv []byte, aad []byte, tagLength uint) *Mechanism {
	// GCM parameters:
	// - 8 bytes for IV length
	// - IV bytes
	// - 8 bytes for AAD length
	// - AAD bytes
	// - 8 bytes for tag length

	params := make([]byte, 8+len(iv)+8+len(aad)+8)

	// IV length
	binary.LittleEndian.PutUint64(params[0:8], uint64(len(iv)))

	// IV
	copy(params[8:8+len(iv)], iv)

	// AAD length
	binary.LittleEndian.PutUint64(params[8+len(iv):16+len(iv)], uint64(len(aad)))

	// AAD
	copy(params[16+len(iv):16+len(iv)+len(aad)], aad)

	// Tag length
	binary.LittleEndian.PutUint64(params[16+len(iv)+len(aad):24+len(iv)+len(aad)], uint64(tagLength))

	return NewMechanism(CKM_AES_GCM, params)
}

// NewMechanismECKeyPairGen creates an EC key pair generation mechanism
func NewMechanismECKeyPairGen() *Mechanism {
	return NewMechanism(CKM_EC_KEY_PAIR_GEN, nil)
}

// NewMechanismECDSA creates an ECDSA mechanism
func NewMechanismECDSA() *Mechanism {
	return NewMechanism(CKM_ECDSA, nil)
}

// NewMechanismECDSAWithHash creates an ECDSA mechanism with the given hash algorithm
func NewMechanismECDSAWithHash(hashAlg MechanismType) *Mechanism {
	switch hashAlg {
	case CKM_SHA_1:
		return NewMechanism(CKM_ECDSA_SHA1, nil)
	case CKM_SHA256:
		return NewMechanism(CKM_ECDSA_SHA256, nil)
	default:
		return NewMechanism(CKM_ECDSA, nil)
	}
}

// NewMechanismECDH creates an ECDH key derivation mechanism with the given parameters
func NewMechanismECDH(publicData []byte) *Mechanism {
	// ECDH parameters:
	// - 8 bytes for KDF type (0 = NULL)
	// - 8 bytes for shared data length (0 = no shared data)
	// - 8 bytes for public data length
	// - Public data bytes

	params := make([]byte, 24+len(publicData))

	// KDF type (0 = NULL)
	binary.LittleEndian.PutUint64(params[0:8], 0)

	// Shared data length (0 = no shared data)
	binary.LittleEndian.PutUint64(params[8:16], 0)

	// Public data length
	binary.LittleEndian.PutUint64(params[16:24], uint64(len(publicData)))

	// Public data
	copy(params[24:24+len(publicData)], publicData)

	return NewMechanism(CKM_ECDH1_DERIVE, params)
}
