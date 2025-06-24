package main

import (
	"fmt"

	"github.com/yeaops/gopkcs11"
)

// VersionExample demonstrates version detection and vendor support checking
func mainVersion() {
	fmt.Println("=== gopkcs11 Version Detection Example ===")

	// This example shows how to detect compile-time and runtime versions
	exampleVersionDetection()
	exampleVendorDetection()
}

func exampleVersionDetection() {
	fmt.Println("\n--- Version Detection ---")

	// Create a context (this example won't actually load a library)
	ctx, err := gopkcs11.New("/path/to/nonexistent/library.so")
	if err != nil {
		// Expected to fail without a real library, but we can still check compile-time info
		fmt.Printf("Note: Library load failed (expected): %v\n", err)
	}

	// Show compile-time version information
	if ctx != nil {
		major, minor := ctx.CompileTimeVersion()
		fmt.Printf("Compile-time PKCS#11 version: %d.%d\n", major, minor)

		// Check runtime module version (if library was loaded)
		runtimeMajor, runtimeMinor := ctx.Version()
		fmt.Printf("Runtime PKCS#11 version: %d.%d\n", runtimeMajor, runtimeMinor)

		// Demonstrate version-specific feature checking
		checkVersionFeatures(ctx)
	} else {
		fmt.Println("Cannot check version without loading a library")
	}
}

func exampleVendorDetection() {
	fmt.Println("\n--- Vendor Support Detection ---")

	// Create a context
	ctx, err := gopkcs11.New("/path/to/nonexistent/library.so")
	if err != nil {
		fmt.Printf("Note: Library load failed (expected): %v\n", err)
		return
	}
	defer ctx.Finalize()

	// Check compile-time vendor support
	fmt.Printf("Utimaco support compiled in: %v\n", ctx.HasUtimacoSupport())

	// Check runtime vendor support (requires actual library)
	fmt.Printf("Thales vendor support: %v\n", ctx.SupportsVendor("thales"))
	fmt.Printf("Utimaco vendor support: %v\n", ctx.SupportsVendor("utimaco"))

	// Example of accessing vendor extensions
	demonstrateVendorExtensions(ctx)
}

func checkVersionFeatures(ctx *gopkcs11.Context) {
	fmt.Println("\n--- Feature Support ---")

	// Check for PKCS#11 v3.0 specific features
	features := ctx.SupportedFeatures()
	fmt.Printf("Supported features: %v\n", features)

	// Check specific features
	if ctx.SupportsFeature("multipleAuth") {
		fmt.Println("✓ Multiple authentication support (v3.0)")
	} else {
		fmt.Println("✗ Multiple authentication not supported")
	}

	if ctx.SupportsFeature("extendedParams") {
		fmt.Println("✓ Extended parameters support (v3.0)")
	} else {
		fmt.Println("✗ Extended parameters not supported")
	}

	if ctx.SupportsFeature("profileAttributes") {
		fmt.Println("✓ Profile attributes support (v3.0)")
	} else {
		fmt.Println("✗ Profile attributes not supported")
	}
}

func demonstrateVendorExtensions(ctx *gopkcs11.Context) {
	fmt.Println("\n--- Vendor Extensions ---")

	// Try to access Utimaco extensions
	if ctx.HasUtimacoSupport() {
		fmt.Println("Utimaco extensions are compiled in")

		utimacoExt, err := ctx.UtimacoExtension()
		if err != nil {
			fmt.Printf("Cannot access Utimaco extension: %v\n", err)
		} else {
			fmt.Println("✓ Utimaco extension available")
			// In a real scenario, you would use utimacoExt for vendor-specific operations
			_ = utimacoExt
		}
	} else {
		fmt.Println("Utimaco extensions not compiled in")
		fmt.Println("To enable: rebuild with 'make build-utimaco' or CGO_CFLAGS=\"-DUTIMACO_HSM\"")
	}

	// Try to access Thales extensions
	thalesExt, err := ctx.ThalesExtension()
	if err != nil {
		fmt.Printf("Cannot access Thales extension: %v\n", err)
	} else {
		fmt.Println("✓ Thales extension available")
		// In a real scenario, you would use thalesExt for vendor-specific operations
		_ = thalesExt
	}
}

// PrintBuildConfiguration shows the current build configuration
func PrintBuildConfiguration() {
	fmt.Println("=== Build Configuration ===")

	// Note: This would typically be called from a context instance
	// Here we show what the output would look like
	fmt.Println("PKCS#11 Version: v2.4 (default) or v3.0 (with PKCS11_V30)")
	fmt.Println("Utimaco Support: Enabled with UTIMACO_HSM flag")
	fmt.Println("Build Commands:")
	fmt.Println("  Default:          make build")
	fmt.Println("  PKCS#11 v3.0:     make build-v30")
	fmt.Println("  Utimaco support:  make build-utimaco")
	fmt.Println("  v3.0 + Utimaco:   make build-v30-utimaco")
}

func init() {
	// Print build configuration when the package is imported
	PrintBuildConfiguration()
	mainVersion()
}
