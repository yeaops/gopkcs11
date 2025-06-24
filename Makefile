# gopkcs11 Build Configuration
# =========================

.PHONY: all build build-v24 build-v30 build-utimaco test clean fmt vet lint

# Default build (PKCS#11 v2.4)
all: build

# Build with PKCS#11 v2.4 (default)
build: build-v24

build-v24:
	@echo "Building with PKCS#11 v2.4 support..."
	CGO_ENABLED=1 go build ./...

# Build with PKCS#11 v3.0
build-v30:
	@echo "Building with PKCS#11 v3.0 support..."
	CGO_ENABLED=1 CGO_CFLAGS="-DPKCS11_V30" go build ./...

# Build with Utimaco HSM support (v2.4 + Utimaco extensions)
build-utimaco:
	@echo "Building with PKCS#11 v2.4 + Utimaco HSM support..."
	CGO_ENABLED=1 CGO_CFLAGS="-DUTIMACO_HSM" go build ./...

# Build with PKCS#11 v3.0 + Utimaco support
build-v30-utimaco:
	@echo "Building with PKCS#11 v3.0 + Utimaco HSM support..."
	CGO_ENABLED=1 CGO_CFLAGS="-DPKCS11_V30 -DUTIMACO_HSM" go build ./...

# Testing
test:
	@echo "Running tests..."
	go test ./...

test-v30:
	@echo "Running tests with PKCS#11 v3.0..."
	CGO_ENABLED=1 CGO_CFLAGS="-DPKCS11_V30" go test ./...

test-utimaco:
	@echo "Running tests with Utimaco support..."
	CGO_ENABLED=1 CGO_CFLAGS="-DUTIMACO_HSM" go test ./...

# Code quality
fmt:
	@echo "Formatting code..."
	go fmt ./...

vet:
	@echo "Running go vet..."
	go vet ./...

lint:
	@echo "Running golangci-lint..."
	golangci-lint run

# Dependency management
deps:
	@echo "Tidying dependencies..."
	go mod tidy

# Clean
clean:
	@echo "Cleaning build artifacts..."
	go clean ./...

# Help
help:
	@echo "Available targets:"
	@echo "  build        - Build with PKCS#11 v2.4 (default)"
	@echo "  build-v24    - Build with PKCS#11 v2.4 explicitly"
	@echo "  build-v30    - Build with PKCS#11 v3.0"
	@echo "  build-utimaco - Build with Utimaco HSM support"
	@echo "  build-v30-utimaco - Build with PKCS#11 v3.0 + Utimaco"
	@echo "  test         - Run tests"
	@echo "  test-v30     - Run tests with PKCS#11 v3.0"
	@echo "  test-utimaco - Run tests with Utimaco support"
	@echo "  fmt          - Format code"
	@echo "  vet          - Run go vet"
	@echo "  lint         - Run golangci-lint"
	@echo "  deps         - Tidy dependencies"
	@echo "  clean        - Clean build artifacts"
	@echo "  help         - Show this help"