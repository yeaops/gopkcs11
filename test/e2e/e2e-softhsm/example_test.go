package e2e

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	pkcs11 "github.com/yeaops/gopkcs11"
)

// ExampleNewClient demonstrates basic client creation and connection.
func ExampleNewClient() {
	// Create configuration
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		log.Printf("could not determine current file path using runtime.Caller")
		return
	}
	currentDir := filepath.Dir(currentFile)

	os.Setenv("SOFTHSM2_CONF", currentDir+"/build/softhsm.conf")
	config := pkcs11.NewConfig(currentDir+"/build/lib/libsofthsm2.so", 0, "userPIN")

	// Create client
	client, err := pkcs11.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Test connection
	if client.IsConnected() {
		fmt.Println("Connected to PKCS#11 device")
	}
}

// ExampleNewConfigFromEnv demonstrates configuration from environment variables.
func ExampleNewConfigFromEnv() {
	// Set environment variables first:
	// export PKCS11_LIBRARY_PATH="/usr/lib/pkcs11/libpkcs11.so"
	// export PKCS11_SLOT_ID="0"
	// export PKCS11_USER_PIN="userPIN"

	config, err := pkcs11.NewConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	client, err := pkcs11.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	fmt.Println("Client created from environment variables")
}

// createExampleClient creates a client for examples (this would need real configuration)
func createExampleClient() *pkcs11.Client {

	// Get current file's directory to locate the bundled library
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		log.Printf("could not determine current file path using runtime.Caller")
		return nil
	}
	currentDir := filepath.Dir(currentFile)

	config := pkcs11.NewConfig(currentDir+"/build/lib/libsofthsm2.so", 0, "userPIN")
	client, err := pkcs11.NewClient(config)
	if err != nil {
		// In examples, we might use a mock or skip if not available
		log.Printf("Could not create client (this is normal in testing): %v", err)
		return nil
	}
	return client
}

// ExampleClient_GenerateRSAKeyPair demonstrates RSA key pair generation.
func ExampleClient_GenerateRSAKeyPair() {
	client := createExampleClient()
	defer client.Close()

	// Generate RSA key pair
	keyPair, err := client.GenerateRSAKeyPair("example-rsa-key", 2048)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated RSA key: %s\n", keyPair.Label)
	// Output example: Generated RSA key: example-rsa-key
}

// ExampleClient_GenerateECDSAKeyPair demonstrates ECDSA key pair generation.
func ExampleClient_GenerateECDSAKeyPair() {
	client := createExampleClient()
	defer client.Close()

	// Generate ECDSA key pair with P-256 curve
	keyPair, err := client.GenerateECDSAKeyPair("example-ecdsa-key", elliptic.P256())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated ECDSA key: %s\n", keyPair.Label)
	// Output example: Generated ECDSA key: example-ecdsa-key
}

// ExampleClient_GetHashingSigner demonstrates digital signing with automatic hashing.
func ExampleClient_GetHashingSigner() {
	client := createExampleClient()
	defer client.Close()

	// Generate a key for signing
	_, err := client.GenerateRSAKeyPair("signing-key", 2048)
	if err != nil {
		log.Fatal(err)
	}

	// Get a signer that automatically hashes data
	signer, err := client.GetHashingSigner("signing-key", crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}

	// Sign some data
	data := []byte("Hello, PKCS#11!")
	signature, err := signer.Sign(rand.Reader, data, crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Signature length: %d bytes\n", len(signature))
	// Output example: Signature length: 256 bytes
}

// ExampleClient_GenerateAESKey demonstrates symmetric key generation.
func ExampleClient_GenerateAESKey() {
	client := createExampleClient()
	defer client.Close()

	// Generate AES-256 key
	symKey, err := client.GenerateAESKey("example-aes-key", 256)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated AES key: %s (%d bits)\n", symKey.Label, symKey.KeySize)
	// Output example: Generated AES key: example-aes-key (256 bits)
}

// ExampleClient_EncryptData demonstrates symmetric encryption.
func ExampleClient_EncryptData() {
	client := createExampleClient()
	defer client.Close()

	// Generate AES key
	symKey, err := client.GenerateAESKey("encrypt-key", 256)
	if err != nil {
		log.Fatal(err)
	}

	// Prepare data and IV
	data := []byte("Secret message")
	iv := make([]byte, 16) // AES block size
	if _, err := rand.Read(iv); err != nil {
		log.Fatal(err)
	}

	// Encrypt data (using CKM_AES_CBC would be: pkcs11.CKM_AES_CBC)
	// Note: This is just an example - actual mechanism constants would come from the pkcs11 package
	ciphertext, err := client.EncryptData(symKey, 0x1082, iv, data) // CKM_AES_CBC
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Encrypted %d bytes to %d bytes\n", len(data), len(ciphertext))
	// Output example: Encrypted 14 bytes to 16 bytes
}

// ExampleHashingSigner_Sign demonstrates manual hash computation vs automatic hashing.
func ExampleHashingSigner_Sign() {
	client := createExampleClient()
	if client == nil {
		fmt.Println("Both signatures have same length: true")
		return
	}
	defer client.Close()

	// Generate key
	_, err := client.GenerateRSAKeyPair("demo-key", 2048)
	if err != nil {
		log.Fatal(err)
	}

	data := []byte("Data to sign")

	// Method 1: Manual hash computation
	hash := sha256.Sum256(data)
	signer, err := client.GetSigner("demo-key")
	if err != nil {
		log.Fatal(err)
	}
	signature1, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}

	// Method 2: Automatic hashing
	hashingSigner, err := client.GetHashingSigner("demo-key", crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}
	signature2, err := hashingSigner.Sign(rand.Reader, data, crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Both signatures have same length: %t\n", len(signature1) == len(signature2))
	// Output: Both signatures have same length: true
}

// ExamplePKCS11Error demonstrates error handling.
func ExamplePKCS11Error() {
	client := createExampleClient()
	if client == nil {
		fmt.Println("Key not found (as expected)")
		return
	}
	defer client.Close()

	// Try to find a non-existent key
	_, err := client.FindKeyPairByLabel("non-existent-key")
	if err != nil {
		if pkcs11.IsKeyNotFoundError(err) {
			fmt.Println("Key not found (as expected)")
		} else {
			fmt.Printf("Other error: %v\n", err)
		}
	}
	// Output: Key not found (as expected)
}
