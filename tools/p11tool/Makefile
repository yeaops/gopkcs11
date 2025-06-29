BINARY_NAME=p11tool
BUILD_DIR=build
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

.PHONY: build clean install test

build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME) .

clean:
	rm -rf $(BUILD_DIR)

install: build
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/

test:
	go test ./...

deps:
	go mod tidy
	go mod download

.DEFAULT_GOAL := build