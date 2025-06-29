package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"flag"

	"github.com/pkg/errors"
	"github.com/yeaops/gopkcs11"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "generate":
		generateKey(args)
	case "list":
		listKeys(args)
	case "import":
		importKey(args)
	case "export":
		exportKey(args)
	case "sign":
		signData(args)
	case "decrypt":
		decryptData(args)
	case "info":
		showKeyInfo(args)
	case "delete":
		deleteKey(args)
	case "version":
		fmt.Printf("p11tool v%s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`p11tool - PKCS#11 密码学操作工具

用法:
  p11tool <命令> [选项]

命令:
  generate   生成密钥对
  list       列出所有密钥
  import     导入私钥
  export     导出公钥
  sign       数字签名
  decrypt    解密数据
  info       显示密钥信息
  delete     删除密钥
  version    显示版本信息
  help       显示帮助信息

生成密钥对:
  p11tool generate --type rsa --size 2048 --label mykey [--lib /path/to/lib] [--slot 0] [--pin 1234]
  p11tool generate --type ecdsa --curve p256 --label mykey [--lib /path/to/lib] [--slot 0] [--pin 1234]
  p11tool generate --type ed25519 --label mykey [--lib /path/to/lib] [--slot 0] [--pin 1234]

列出密钥:
  p11tool list [--lib /path/to/lib] [--slot 0] [--pin 1234]

导入私钥:
  p11tool import --file private.pem --label mykey [--lib /path/to/lib] [--slot 0] [--pin 1234]

导出公钥:
  p11tool export --label mykey --format pem [--output public.pem] [--lib /path/to/lib] [--slot 0] [--pin 1234]

数字签名:
  p11tool sign --label mykey --data "hello world" [--output signature.bin] [--lib /path/to/lib] [--slot 0] [--pin 1234]
  p11tool sign --label mykey --file data.txt [--output signature.bin] [--lib /path/to/lib] [--slot 0] [--pin 1234]

解密数据:
  p11tool decrypt --label mykey --file encrypted.bin [--output decrypted.txt] [--lib /path/to/lib] [--slot 0] [--pin 1234]

显示密钥信息:
  p11tool info --label mykey [--lib /path/to/lib] [--slot 0] [--pin 1234]

删除密钥:
  p11tool delete --label mykey [--lib /path/to/lib] [--slot 0] [--pin 1234]

全局选项:
  --lib     PKCS#11 库文件路径 (默认: /usr/lib/softhsm/libsofthsm2.so)
  --slot    PKCS#11 插槽号 (默认: 0)
  --pin     用户PIN码 (默认: 1234)

环境变量:
  PKCS11_LIB    设置默认的PKCS#11库路径
  PKCS11_SLOT   设置默认的插槽号
  PKCS11_PIN    设置默认的PIN码
`)
}

func parseGlobalFlags(args []string) (*gopkcs11.Config, []string) {
	fs := flag.NewFlagSet("global", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	lib := fs.String("lib", getEnvOrDefault("PKCS11_LIB", "/usr/lib/softhsm/libsofthsm2.so"), "PKCS#11 library path")
	slot := fs.Int("slot", getEnvIntOrDefault("PKCS11_SLOT", 0), "PKCS#11 slot number")
	pin := fs.String("pin", getEnvOrDefault("PKCS11_PIN", "1234"), "User PIN")

	remainingArgs := []string{}
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--lib") ||
			strings.HasPrefix(args[i], "--slot") ||
			strings.HasPrefix(args[i], "--pin") {
			if strings.Contains(args[i], "=") {
				// Handle --flag=value format
				fs.Parse([]string{args[i]})
			} else if i+1 < len(args) {
				// Handle --flag value format
				fs.Parse([]string{args[i], args[i+1]})
				i++ // Skip the value
			}
		} else {
			remainingArgs = append(remainingArgs, args[i])
		}
	}

	slotID := uint(*slot)
	config := &gopkcs11.Config{
		LibraryPath: *lib,
		SlotID:      &slotID,
		UserPIN:     *pin,
	}

	return config, remainingArgs
}

func getEnvOrDefault(env, defaultValue string) string {
	if value := os.Getenv(env); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(env string, defaultValue int) int {
	if value := os.Getenv(env); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func createClient(config *gopkcs11.Config) (*gopkcs11.Client, error) {
	client, err := gopkcs11.NewClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create PKCS#11 client")
	}
	return client, nil
}

func generateKey(args []string) {
	config, remainingArgs := parseGlobalFlags(args)

	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	keyType := fs.String("type", "", "Key type (rsa, ecdsa, ed25519)")
	size := fs.Int("size", 2048, "Key size for RSA (2048, 4096)")
	curve := fs.String("curve", "p256", "Curve for ECDSA (p256, p384)")
	label := fs.String("label", "", "Key label")

	fs.Parse(remainingArgs)

	if *keyType == "" || *label == "" {
		fmt.Fprintf(os.Stderr, "Error: --type and --label are required\n")
		os.Exit(1)
	}

	client, err := createClient(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	var keyPair *gopkcs11.KeyPair

	switch strings.ToLower(*keyType) {
	case "rsa":
		keyPair, err = client.GenerateRSAKeyPair(*label, *size)
	case "ecdsa":
		var ellipticCurve elliptic.Curve
		switch strings.ToLower(*curve) {
		case "p256":
			ellipticCurve = elliptic.P256()
		case "p384":
			ellipticCurve = elliptic.P384()
		default:
			fmt.Fprintf(os.Stderr, "Error: Unsupported curve: %s\n", *curve)
			os.Exit(1)
		}
		keyPair, err = client.GenerateECDSAKeyPair(*label, ellipticCurve)
	case "ed25519":
		keyPair, err = client.GenerateED25519KeyPair(*label)
	default:
		fmt.Fprintf(os.Stderr, "Error: Unsupported key type: %s\n", *keyType)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully generated %s key pair with label '%s'\n", strings.ToUpper(*keyType), *label)
	fmt.Printf("Key ID: %s\n", hex.EncodeToString(keyPair.ID))
	fmt.Printf("Key Size: %d bits\n", keyPair.KeySize)
}

func listKeys(args []string) {
	config, _ := parseGlobalFlags(args)

	client, err := createClient(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	keyPairs, err := client.ListKeyPairs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing keys: %v\n", err)
		os.Exit(1)
	}

	if len(keyPairs) == 0 {
		fmt.Println("No keys found")
		return
	}

	fmt.Printf("Found %d key(s):\n\n", len(keyPairs))
	for i, kp := range keyPairs {
		fmt.Printf("%d. Label: %s\n", i+1, kp.Label)
		fmt.Printf("   Type: %s\n", getKeyTypeString(kp.KeyType))
		fmt.Printf("   Size: %d bits\n", kp.KeySize)
		fmt.Printf("   ID: %s\n", hex.EncodeToString(kp.ID))
		fmt.Println()
	}
}

func importKey(args []string) {
	config, remainingArgs := parseGlobalFlags(args)

	fs := flag.NewFlagSet("import", flag.ExitOnError)
	file := fs.String("file", "", "Private key file path")
	label := fs.String("label", "", "Key label")

	fs.Parse(remainingArgs)

	if *file == "" || *label == "" {
		fmt.Fprintf(os.Stderr, "Error: --file and --label are required\n")
		os.Exit(1)
	}

	keyData, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading key file: %v\n", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid PEM format\n")
		os.Exit(1)
	}

	var privateKey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		fmt.Fprintf(os.Stderr, "Error: Unsupported key type: %s\n", block.Type)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing private key: %v\n", err)
		os.Exit(1)
	}

	client, err := createClient(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	keyPair, err := client.ImportKeyPair(*label, privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error importing key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully imported key with label '%s'\n", *label)
	fmt.Printf("Key Type: %s\n", getKeyTypeString(keyPair.KeyType))
	fmt.Printf("Key ID: %s\n", hex.EncodeToString(keyPair.ID))
}

func exportKey(args []string) {
	config, remainingArgs := parseGlobalFlags(args)

	fs := flag.NewFlagSet("export", flag.ExitOnError)
	label := fs.String("label", "", "Key label")
	format := fs.String("format", "pem", "Output format (pem, der)")
	output := fs.String("output", "", "Output file path (default: stdout)")

	fs.Parse(remainingArgs)

	if *label == "" {
		fmt.Fprintf(os.Stderr, "Error: --label is required\n")
		os.Exit(1)
	}

	client, err := createClient(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	keyPair, err := client.FindKeyPairByLabel(*label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding key: %v\n", err)
		os.Exit(1)
	}

	var publicKeyBytes []byte
	switch strings.ToLower(*format) {
	case "pem":
		publicKeyBytes, err = x509.MarshalPKIXPublicKey(keyPair.PublicKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling public key: %v\n", err)
			os.Exit(1)
		}
		block := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		}
		publicKeyBytes = pem.EncodeToMemory(block)
	case "der":
		publicKeyBytes, err = x509.MarshalPKIXPublicKey(keyPair.PublicKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling public key: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Error: Unsupported format: %s\n", *format)
		os.Exit(1)
	}

	if *output == "" {
		fmt.Print(string(publicKeyBytes))
	} else {
		err = os.WriteFile(*output, publicKeyBytes, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Public key exported to %s\n", *output)
	}
}

func signData(args []string) {
	config, remainingArgs := parseGlobalFlags(args)

	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	label := fs.String("label", "", "Key label")
	data := fs.String("data", "", "Data to sign")
	file := fs.String("file", "", "File to sign")
	output := fs.String("output", "", "Output file path (default: stdout)")

	fs.Parse(remainingArgs)

	if *label == "" {
		fmt.Fprintf(os.Stderr, "Error: --label is required\n")
		os.Exit(1)
	}

	if *data == "" && *file == "" {
		fmt.Fprintf(os.Stderr, "Error: either --data or --file is required\n")
		os.Exit(1)
	}

	var inputData []byte
	var err error

	if *data != "" {
		inputData = []byte(*data)
	} else {
		inputData, err = os.ReadFile(*file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input file: %v\n", err)
			os.Exit(1)
		}
	}

	client, err := createClient(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	signer, err := client.GetKeyPairSigner(*label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting signer: %v\n", err)
		os.Exit(1)
	}

	signature, err := signer.Sign(rand.Reader, inputData, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing data: %v\n", err)
		os.Exit(1)
	}

	if *output == "" {
		fmt.Printf("%s\n", hex.EncodeToString(signature))
	} else {
		err = os.WriteFile(*output, signature, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Signature saved to %s\n", *output)
	}
}

func decryptData(args []string) {
	config, remainingArgs := parseGlobalFlags(args)

	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	label := fs.String("label", "", "Key label")
	file := fs.String("file", "", "File to decrypt")
	output := fs.String("output", "", "Output file path (default: stdout)")

	fs.Parse(remainingArgs)

	if *label == "" || *file == "" {
		fmt.Fprintf(os.Stderr, "Error: --label and --file are required\n")
		os.Exit(1)
	}

	encryptedData, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input file: %v\n", err)
		os.Exit(1)
	}

	client, err := createClient(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	decrypter, err := client.GetKeyPairDecrypter(*label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting decrypter: %v\n", err)
		os.Exit(1)
	}

	plaintext, err := decrypter.Decrypt(rand.Reader, encryptedData, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting data: %v\n", err)
		os.Exit(1)
	}

	if *output == "" {
		fmt.Print(string(plaintext))
	} else {
		err = os.WriteFile(*output, plaintext, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Decrypted data saved to %s\n", *output)
	}
}

func showKeyInfo(args []string) {
	config, remainingArgs := parseGlobalFlags(args)

	fs := flag.NewFlagSet("info", flag.ExitOnError)
	label := fs.String("label", "", "Key label")

	fs.Parse(remainingArgs)

	if *label == "" {
		fmt.Fprintf(os.Stderr, "Error: --label is required\n")
		os.Exit(1)
	}

	client, err := createClient(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	keyPair, err := client.FindKeyPairByLabel(*label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Key Information:\n")
	fmt.Printf("  Label: %s\n", keyPair.Label)
	fmt.Printf("  Type: %s\n", getKeyTypeString(keyPair.KeyType))
	fmt.Printf("  Size: %d bits\n", keyPair.KeySize)
	fmt.Printf("  ID: %s\n", hex.EncodeToString(keyPair.ID))

	switch keyPair.KeyType {
	case gopkcs11.KeyPairTypeRSA:
		if rsaPub, ok := keyPair.PublicKey.(*rsa.PublicKey); ok {
			fmt.Printf("  Modulus size: %d bits\n", rsaPub.Size()*8)
			fmt.Printf("  Public exponent: %d\n", rsaPub.E)
		}
	case gopkcs11.KeyPairTypeECDSA:
		if ecdsaPub, ok := keyPair.PublicKey.(*ecdsa.PublicKey); ok {
			fmt.Printf("  Curve: %s\n", ecdsaPub.Curve.Params().Name)
		}
	case gopkcs11.KeyPairTypeED25519:
		if ed25519Pub, ok := keyPair.PublicKey.(ed25519.PublicKey); ok {
			fmt.Printf("  Public key: %s\n", hex.EncodeToString(ed25519Pub))
		}
	}
}

func deleteKey(args []string) {
	config, remainingArgs := parseGlobalFlags(args)

	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	label := fs.String("label", "", "Key label")
	force := fs.Bool("force", false, "Force deletion without confirmation")

	fs.Parse(remainingArgs)

	if *label == "" {
		fmt.Fprintf(os.Stderr, "Error: --label is required\n")
		os.Exit(1)
	}

	if !*force {
		fmt.Printf("Are you sure you want to delete key '%s'? [y/N]: ", *label)
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
			fmt.Println("Deletion cancelled")
			return
		}
	}

	client, err := createClient(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	// Note: Key deletion would need to be implemented in the gopkcs11 library
	// This is a placeholder for the functionality
	fmt.Printf("Key deletion functionality not yet implemented in gopkcs11 library\n")
	fmt.Printf("Would delete key with label: %s\n", *label)
}

func getKeyTypeString(keyType gopkcs11.KeyPairType) string {
	switch keyType {
	case gopkcs11.KeyPairTypeRSA:
		return "RSA"
	case gopkcs11.KeyPairTypeECDSA:
		return "ECDSA"
	case gopkcs11.KeyPairTypeED25519:
		return "ED25519"
	default:
		return "Unknown"
	}
}
