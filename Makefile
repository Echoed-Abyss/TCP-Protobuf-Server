.PHONY: build build-linux test vet clean release

BINARY      := secproto
BUILD_DIR   := build
GO          := go
LDFLAGS     := -s -w
GOFLAGS     := -trimpath

# Default: build for the host platform.
build:
	$(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/secproto

# Static Linux amd64 binary for release.
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-linux-amd64 ./cmd/secproto

# Run all unit and integration tests.
test:
	$(GO) test ./... -v

# Static analysis.
vet:
	$(GO) vet ./...

# Regenerate protobuf (requires protoc + protoc-gen-go).
proto:
	PATH="$$(go env GOPATH)/bin:$$PATH" protoc --go_out=. --go_opt=module=github.com/Echoed-Abyss/TCP-Protobuf-Server proto/handshake.proto

# Vendor dependencies for offline builds.
vendor:
	$(GO) mod vendor

clean:
	rm -rf $(BUILD_DIR) vendor

# Full release pipeline.
release: vet test build-linux
	@echo "Built $(BUILD_DIR)/$(BINARY)-linux-amd64"
