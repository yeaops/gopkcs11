package utimaco

import (
	_ "embed"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/yeaops/gopkcs11"
)

const (
	CKU_CS_GENERIC = 0x83
)

var (
	mux = sync.Mutex{}

	tmplFuncs = template.FuncMap{"join": strings.Join}

	//go:embed "utimaco-cs_pkcs11_R3.cfg.tmpl"
	cfgTmplStr string
	cfgTmpl    = template.Must(template.New("utimaco-cs_pkcs11_R3.cfg").Funcs(tmplFuncs).Parse(cfgTmplStr))
)

func generateUtimacoConfigFile(filepath string, config Config) error {
	err := os.MkdirAll(path.Dir(filepath), 0755)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	err = cfgTmpl.Execute(file, config.Client)
	if err != nil {
		return err
	}

	return nil
}

type Config struct {
	DataDir     string
	AdminPin    string
	LibraryPath string
	Client      struct {
		Global       UtimacoClientGlobalConfig
		CryptoServer UtimacoClientCryptoServerConfig
		KeyStorage   UtimacoClientKeyStorageConfig
	}
}

type TestUtimaco struct {
	libraryPath string
	tokenDir    string
	configFile  string
	config      Config
	cleanup     func()
}

// NewTestUtimaco creates a new test instance for Utimaco HSM
func NewTestUtimaco() (*TestUtimaco, error) {
	utimaco := &TestUtimaco{}

	if os.Getenv("UTIMACO_ADMIN_PIN") == "" {
		os.Setenv("UTIMACO_ADMIN_PIN", "ADMIN,"+os.Getenv("HOME")+"/.utimaco/ADMIN_SIM.key")
	}

	if os.Getenv("UTIMACO_DEVICE") == "" {
		os.Setenv("UTIMACO_DEVICE", "3005@127.0.0.1")
	}

	err := utimaco.setup()
	if err != nil {
		return nil, fmt.Errorf("failed to setup Utimaco test environment: %w", err)
	}

	return utimaco, nil
}

// setup initializes the Utimaco test environment
func (u *TestUtimaco) setup() error {
	// Get library path from environment or use default
	libraryPath := os.Getenv("PKCS11_LIBRARY_PATH")
	if libraryPath == "" {
		// Try common Utimaco library paths
		candidates := []string{
			os.Getenv("HOME") + "/.utimaco/libcs_pkcs11_R3.so",
			"/usr/lib/libcs_pkcs11_R3.so",
			"/opt/utimaco/lib/libcs_pkcs11_R3.so",
			"/usr/local/lib/libcs_pkcs11_R3.so",
		}

		for _, path := range candidates {
			if _, err := os.Stat(path); err == nil {
				libraryPath = path
				break
			}
		}

		if libraryPath == "" {
			return fmt.Errorf("utimaco PKCS#11 library not found - install Utimaco CryptoServer or set PKCS11_LIBRARY_PATH")
		}
	}
	u.libraryPath = libraryPath

	// Create temporary directory for this test
	tempDir := filepath.Join("test-temp", fmt.Sprintf("tokens-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	// Get the directory of the current file
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return fmt.Errorf("failed to get current file path")
	}
	tempDir = path.Join(path.Dir(filename), tempDir)
	u.tokenDir = tempDir

	// Setup default configuration
	u.config = Config{
		DataDir:     tempDir,
		AdminPin:    os.Getenv("UTIMACO_ADMIN_PIN"),
		LibraryPath: libraryPath,
		Client: struct {
			Global       UtimacoClientGlobalConfig
			CryptoServer UtimacoClientCryptoServerConfig
			KeyStorage   UtimacoClientKeyStorageConfig
		}{
			Global: UtimacoClientGlobalConfig{
				Logpath:           tempDir,
				Logging:           4, // ERROR level
				Logsize:           "10mb",
				SlotMultiSession:  true,
				SlotCount:         120,
				KeepLeadZeros:     false,
				FallbackInterval:  0,
				KeepAlive:         false,
				ConnectionTimeout: 30000,
				CommandTimeout:    30000,
				ForceOSLocking:    false,
				KeysExternal:      false,
			},
			CryptoServer: UtimacoClientCryptoServerConfig{
				Device: os.Getenv("UTIMACO_DEVICE"),
			},
			KeyStorage: UtimacoClientKeyStorageConfig{
				KeyStorageType:      "Legacy",
				KeyStorageConfig:    path.Join(tempDir, "P11.pks"),
				KeyStorageReconnect: 3,
			},
		},
	}

	// if no admin pin specified, use default
	// Environment variable UTIMACO_ADMIN_PIN can be used to override the default
	if u.config.AdminPin == "" {
		u.config.AdminPin = "12345678"
	}

	// If no device specified, use simulator default
	// Environment variable UTIMACO_DEVICE can be used to override the default
	if u.config.Client.CryptoServer.Device == "" {
		u.config.Client.CryptoServer.Device = "3001@127.0.0.1"
	}

	configFile := filepath.Join(tempDir, "cs_pkcs11_R3.cfg")
	if err := generateUtimacoConfigFile(configFile, u.config); err != nil {
		return fmt.Errorf("failed to generate config file: %w", err)
	}
	u.configFile = configFile

	// Set environment variable for Utimaco config
	oldConfig := os.Getenv("CS_PKCS11_R3_CFG")
	os.Setenv("CS_PKCS11_R3_CFG", configFile)
	// os.Setenv("CS_PKCS11_R3_CFG", os.Getenv("HOME")+"/.utimaco/cs_pkcs11_R3.cfg")

	// Setup cleanup function
	u.cleanup = func() {
		// Restore original config
		if oldConfig != "" {
			os.Setenv("CS_PKCS11_R3_CFG", oldConfig)
		} else {
			os.Unsetenv("CS_PKCS11_R3_CFG")
		}
		// Clean up temp files
		os.RemoveAll(tempDir)
	}

	return nil
}

// CreateToken creates a test token for Utimaco HSM
func (u *TestUtimaco) CreateToken(t testing.TB) *gopkcs11.Token {
	t.Helper()

	var tokenLabel, soPin, userPin string
	tokenLabel = "test-token"
	soPin = "12345678"
	userPin = "12345678"

	slotID, err := u.createToken(tokenLabel, soPin, userPin)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	config := &gopkcs11.Config{
		LibraryPath: u.libraryPath,
		SlotID:      slotID,
		UserPIN:     userPin,
	}

	token, err := gopkcs11.NewToken(config)
	if err != nil {
		t.Fatalf("could not create Utimaco token: %v", err)
	}

	return token
}

func (u *TestUtimaco) createToken(tokenLabel, soPin, userPin string) (*uint, error) {
	mux.Lock()
	defer mux.Unlock()

	// init ctx
	// load SoftHSM library
	p11Ctx := pkcs11.New(u.libraryPath)
	if p11Ctx == nil {
		return nil, fmt.Errorf("could not create PKCS#11 context, path: %s", u.libraryPath)
	}
	defer p11Ctx.Destroy()

	if err := p11Ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("could not initialize PKCS#11 library: %v", err)
	}
	defer p11Ctx.Finalize()

	slot, err := u.findNotUseSlot(p11Ctx)
	if err != nil || slot == nil {
		return nil, fmt.Errorf("could not find available slot: %v", err)
	}

	err = u.initializeSoftHSMToken(p11Ctx, *slot, tokenLabel, soPin, userPin)
	if err != nil {
		return nil, fmt.Errorf("could not initialize SoftHSM token: %v", err)
	}

	return slot, nil
}

func (u *TestUtimaco) initializeSoftHSMToken(p11Ctx *pkcs11.Ctx, slot uint, tokenLabel, soPin, userPin string) error {

	// Step 1: Login with custom ADMIN user (Utimaco specific)
	// Open session for ADMIN operations
	session, err := p11Ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("could not open session for ADMIN: %v", err)
	}
	defer p11Ctx.CloseSession(session)

	// Login as ADMIN (Utimaco uses CKU_CONTEXT_SPECIFIC for ADMIN)
	err = p11Ctx.Login(session, CKU_CS_GENERIC, u.config.AdminPin)
	if err != nil {
		return fmt.Errorf("could not login as ADMIN: %v", err)
	}

	// Step 2: Initialize token and SO password with ADMIN user
	soPinInit := soPin + "0"
	err = p11Ctx.InitToken(slot, soPinInit, tokenLabel)
	if err != nil {
		return fmt.Errorf("could not initialize token: %v", err)
	}

	// Step 3: Logout ADMIN
	err = p11Ctx.Logout(session)
	if err != nil {
		return fmt.Errorf("could not logout ADMIN: %v", err)
	}

	// Step 4: Login as SO to update password
	err = p11Ctx.Login(session, pkcs11.CKU_SO, soPinInit)
	if err != nil {
		return fmt.Errorf("could not login as SO: %v", err)
	}

	// Update SO PIN to final password
	err = p11Ctx.SetPIN(session, soPinInit, soPin)
	if err != nil {
		return fmt.Errorf("could not update SO PIN: %v", err)
	}

	// Step 5: Logout SO
	err = p11Ctx.Logout(session)
	if err != nil {
		return fmt.Errorf("could not logout SO after PIN change: %v", err)
	}

	// Step 6: Login with new SO password
	err = p11Ctx.Login(session, pkcs11.CKU_SO, soPin)
	if err != nil {
		return fmt.Errorf("could not login as SO with new PIN: %v", err)
	}

	// Step 7: Initialize User PIN
	userPinInit := userPin + "0"
	err = p11Ctx.InitPIN(session, userPinInit)
	if err != nil {
		return fmt.Errorf("could not initialize user PIN: %v", err)
	}

	// Step 8: Logout SO
	err = p11Ctx.Logout(session)
	if err != nil {
		return fmt.Errorf("could not logout SO after user PIN init: %v", err)
	}

	// Step 9: Login as User to change to final User PIN
	err = p11Ctx.Login(session, pkcs11.CKU_USER, userPinInit)
	if err != nil {
		return fmt.Errorf("could not login as User: %v", err)
	}

	// Update User PIN to final password
	err = p11Ctx.SetPIN(session, userPinInit, userPin)
	if err != nil {
		return fmt.Errorf("could not update User PIN: %v", err)
	}

	// Step 10: Final logout to complete initialization
	err = p11Ctx.Logout(session)
	if err != nil {
		return fmt.Errorf("could not logout User after final PIN change: %v", err)
	}

	return nil
}

func (u *TestUtimaco) findNotUseSlot(ctx *pkcs11.Ctx) (*uint, error) {
	// load SoftHSM library
	allSlots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("could not get slot list: %v", err)
	}

	for _, slot := range allSlots {
		tokenInfo, err := ctx.GetTokenInfo(slot)
		if err != nil {
			return nil, fmt.Errorf("could not get token info: %v", err)
		}

		if tokenInfo.Flags&pkcs11.CKF_TOKEN_INITIALIZED != 0 {
			continue
		} else {
			result := slot
			return &result, nil
		}
	}

	return nil, fmt.Errorf("no available slot found")
}

// Cleanup cleans up the test environment
func (u *TestUtimaco) Cleanup() error {
	if u.cleanup != nil {
		u.cleanup()
	}
	return nil
}

type UtimacoClientGlobalConfig struct {
	// Path to the logfile (name of logfile is attached by the API)
	Logpath string
	// Log level (0 = NONE; 1 = ERROR; 2 = WARNING; 3 = INFO; 4 = TRACE)
	Logging int
	// Maximum size of the logfile in bytes (file is rotated with a backup file if full)
	Logsize string

	// If true, every session establishes its own connection
	SlotMultiSession bool

	// Maximum number of slots that can be used
	SlotCount int

	// If true, leading zeroes of decryption operations will be kept
	KeepLeadZeros bool

	// Configures load balancing mode ( == 0 ) or failover mode ( > 0 )
	// In failover mode, n specifies the interval (in seconds) after which a reconnection attempt to the failed CryptoServer is started
	FallbackInterval int

	// Prevents expiring session after inactivity of 15 minutes
	KeepAlive bool

	// Timeout of the open connection command in ms
	ConnectionTimeout int64

	// Timeout of command execution in ms
	CommandTimeout int64

	// List of official PKCS#11 mechanisms which should be customized
	CustomMechanisms []string

	// Enforce thread-safety by using the operating system locking primitives
	ForceOSLocking bool

	// Created/generated keys are stored in an external or internal database
	KeysExternal bool

	// Path to the external keystore
	// If KeyStore is defined the external keystore will be created and used at the defined location
	KeyStore string
}

type UtimacoClientKeyStorageConfig struct {
	// KeyStorageType (Legacy: Legacy SDB file; ODBC: Database via ODBC)
	KeyStorageType string

	// When KeyStorageType is Legacy, KeyStorageConfig is Path to the external keystore,
	// When KeyStorageType is ODBC, KeyStorageConfig should be "DSN=PSQL Ucapi External Storage"
	KeyStorageConfig string

	// Number of reconnection attempts to ODBC database
	KeyStorageReconnect int
}

type UtimacoClientCryptoServerConfig struct {
	// Device specifier (here: internal PCI device)
	// For Unix
	//    /dev/cs2.0
	// For Windows
	//    PCI:0
	// Device specifier (here: cHSM on local u.trust Anchor device - last number represents cHSM slot (1))
	//    /dev/cs2.0.1
	// Device specifier (here: local simulator)
	//    3001@10.60.20.61
	// Device specifier (here: cluster of simulators)
	//   { 3001@127.0.0.1 3003@127.0.0.1 }
	// Device specifier (here: cHSM on remote u.trust Anchor device - port = base port (4000) + cHSM slot (1))
	//    4001@192.168.0.1
	// Device specifier (here: remote device with IP address 192.168.0.1)
	//    192.168.0.1
	// Device specifier (here: cluster of remote devices - first as above, others using format <port>@<ip>)
	//    { 192.168.0.1 288@192.168.0.2 4001@192.168.0.3 }
	Device string
}
