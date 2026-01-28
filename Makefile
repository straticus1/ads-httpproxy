# Makefile for ads-httpproxy

BINARY_NAME=ads-httpproxy
ADMIN_BINARY=ads-admin
MIGRATION_BINARY=squid2ads
BUILD_DIR=bin

.PHONY: all build clean test run docker

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/proxy
	@echo "Building $(ADMIN_BINARY)..."
	go build -o $(BUILD_DIR)/$(ADMIN_BINARY) ./cmd/ads-admin
	@echo "Building $(MIGRATION_BINARY)..."
	go build -o $(BUILD_DIR)/$(MIGRATION_BINARY) ./cmd/squid2ads

clean:
	@echo "Cleaning up..."
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY_NAME) $(ADMIN_BINARY) $(MIGRATION_BINARY) proxy admin squid2ads
	@echo "Clean complete."

test:
	go test -v ./...

run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

docker:
	docker build -t $(BINARY_NAME):latest .
