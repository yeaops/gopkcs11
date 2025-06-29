package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"golang.org/x/crypto/ssh"
)

type KeyType string

const (
	RSA        KeyType = "rsa"
	DSA        KeyType = "dsa"
	ECDSA      KeyType = "ecdsa"
	ECDSA_SK   KeyType = "ecdsa-sk"
	ED25519    KeyType = "ed25519"
	ED25519_SK KeyType = "ed25519-sk"
)

type Format string

const (
	PEM_FORMAT        Format = "pem"
	DER_FORMAT        Format = "der"
	SSH_FORMAT        Format = "ssh"
	OPENSSH_FORMAT    Format = "openssh"
)

type Command string

const (
	GENERATE_CMD Command = "generate"
	CONVERT_CMD  Command = "convert"
)

func main() {
	var (
		cmd        = flag.String("cmd", "", "Command: generate, convert")
		keyType    = flag.String("type", "rsa", "Key type: rsa, dsa, ecdsa, ecdsa-sk, ed25519, ed25519-sk")
		keySize    = flag.Int("size", 2048, "Key size (for RSA: 1024,2048,4096; for DSA: 1024,2048,3072; for ECDSA: 256,384,521)")
		outputFile = flag.String("output", "", "Output file path")
		inputFile  = flag.String("input", "", "Input file path (for conversion)")
		fromFormat = flag.String("from", "", "Source format: pem, der, ssh")
		toFormat   = flag.String("to", "", "Target format: pem, der, ssh")
		help       = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help || *cmd == "" {
		showHelp()
		return
	}

	switch Command(*cmd) {
	case GENERATE_CMD:
		err := generateKey(KeyType(*keyType), *keySize, *outputFile)
		if err != nil {
			log.Fatalf("Failed to generate key: %v", err)
		}
	case CONVERT_CMD:
		if *inputFile == "" || *fromFormat == "" || *toFormat == "" {
			log.Fatal("Convert command requires -input, -from, and -to flags")
		}
		err := convertKey(*inputFile, Format(*fromFormat), Format(*toFormat), *outputFile)
		if err != nil {
			log.Fatalf("Failed to convert key: %v", err)
		}
	default:
		log.Fatalf("Unknown command: %s", *cmd)
	}
}

func showHelp() {
	fmt.Println("keyfo - SSH Key Format Tool")
	fmt.Println("\nUsage:")
	fmt.Println("  keyfo -cmd generate -type <key_type> [-size <key_size>] [-output <file>]")
	fmt.Println("  keyfo -cmd convert -input <file> -from <format> -to <format> [-output <file>]")
	fmt.Println("\nKey Types:")
	fmt.Println("  rsa, dsa, ecdsa, ecdsa-sk, ed25519, ed25519-sk")
	fmt.Println("\nFormats:")
	fmt.Println("  pem, der, ssh")
	fmt.Println("\nExamples:")
	fmt.Println("  keyfo -cmd generate -type ed25519 -output my_key")
	fmt.Println("  keyfo -cmd convert -input my_key.pub -from ssh -to pem -output my_key.pub.pem")
}

func generateKey(keyType KeyType, keySize int, outputFile string) error {
	var privateKey interface{}
	var err error

	switch keyType {
	case RSA:
		privateKey, err = rsa.GenerateKey(rand.Reader, keySize)
	case DSA:
		params := &dsa.Parameters{}
		err = dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160)
		if err != nil {
			return err
		}
		dsaKey := &dsa.PrivateKey{}
		dsaKey.Parameters = *params
		err = dsa.GenerateKey(dsaKey, rand.Reader)
		privateKey = dsaKey
	case ECDSA:
		var curve elliptic.Curve
		switch keySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		privateKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	case ED25519:
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
	case ECDSA_SK, ED25519_SK:
		return errors.New("security key types not yet supported")
	default:
		return errors.New("unsupported key type")
	}

	if err != nil {
		return err
	}

	privateKeyPEM, err := encodePrivateKeyToPEM(privateKey)
	if err != nil {
		return err
	}

	publicKey, err := getPublicKey(privateKey)
	if err != nil {
		return err
	}

	publicKeySSH, err := encodePublicKeyToSSH(publicKey)
	if err != nil {
		return err
	}

	baseName := outputFile
	if baseName == "" {
		baseName = "id_" + string(keyType)
	}

	err = ioutil.WriteFile(baseName, privateKeyPEM, 0600)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(baseName+".pub", publicKeySSH, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("Generated key pair: %s (private), %s.pub (public)\n", baseName, baseName)
	return nil
}

func convertKey(inputFile string, fromFormat, toFormat Format, outputFile string) error {
	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return err
	}

	var key interface{}
	var isPrivate bool

	switch fromFormat {
	case PEM_FORMAT:
		key, isPrivate, err = parseKeyFromPEM(data)
	case DER_FORMAT:
		key, isPrivate, err = parseKeyFromDER(data)
	case SSH_FORMAT:
		key, isPrivate, err = parseKeyFromSSH(data)
	default:
		return errors.New("unsupported source format")
	}

	if err != nil {
		return err
	}

	var output []byte
	switch toFormat {
	case PEM_FORMAT:
		if isPrivate {
			output, err = encodePrivateKeyToPEM(key)
		} else {
			output, err = encodePublicKeyToPEM(key)
		}
	case DER_FORMAT:
		if isPrivate {
			output, err = encodePrivateKeyToDER(key)
		} else {
			output, err = encodePublicKeyToDER(key)
		}
	case SSH_FORMAT:
		if isPrivate {
			publicKey, err := getPublicKey(key)
			if err != nil {
				return err
			}
			output, err = encodePublicKeyToSSH(publicKey)
		} else {
			output, err = encodePublicKeyToSSH(key)
		}
	default:
		return errors.New("unsupported target format")
	}

	if err != nil {
		return err
	}

	if outputFile == "" {
		fmt.Print(string(output))
	} else {
		err = ioutil.WriteFile(outputFile, output, 0644)
		if err != nil {
			return err
		}
		fmt.Printf("Converted key saved to: %s\n", outputFile)
	}

	return nil
}

func parseKeyFromPEM(data []byte) (interface{}, bool, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, false, errors.New("failed to decode PEM block")
	}

	if strings.Contains(block.Type, "PRIVATE") {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				key, err = x509.ParseECPrivateKey(block.Bytes)
			}
		}
		return key, true, err
	} else {
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		return key, false, err
	}
}

func parseKeyFromDER(data []byte) (interface{}, bool, error) {
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err == nil {
		return key, true, nil
	}

	key, err = x509.ParsePKIXPublicKey(data)
	return key, false, err
}

func parseKeyFromSSH(data []byte) (interface{}, bool, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, false, err
	}
	
	// Convert SSH public key to standard crypto type
	cryptoKey := key.(ssh.CryptoPublicKey).CryptoPublicKey()
	return cryptoKey, false, nil
}

func encodePrivateKeyToPEM(privateKey interface{}) ([]byte, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	return pem.EncodeToMemory(block), nil
}

func encodePublicKeyToPEM(publicKey interface{}) ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	}

	return pem.EncodeToMemory(block), nil
}

func encodePrivateKeyToDER(privateKey interface{}) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(privateKey)
}

func encodePublicKeyToDER(publicKey interface{}) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(publicKey)
}

func encodePublicKeyToSSH(publicKey interface{}) ([]byte, error) {
	sshKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return ssh.MarshalAuthorizedKey(sshKey), nil
}

func getPublicKey(privateKey interface{}) (interface{}, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case ed25519.PrivateKey:
		return key.Public(), nil
	case *dsa.PrivateKey:
		return &key.PublicKey, nil
	default:
		return nil, errors.New("unsupported private key type")
	}
}