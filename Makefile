PLUGIN_NAME ?= zcode
VERSION ?= 0.1.0
BUILD_DIR ?= dist
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GO_LDFLAGS ?= -s -w -X main.pluginVersion=$(VERSION)

EXT_linux = so
EXT_darwin = dylib
EXT_windows = dll
PLUGIN_EXT = $(or $(EXT_$(GOOS)),so)
PLUGIN_OUTPUT ?= $(BUILD_DIR)/$(PLUGIN_NAME).$(PLUGIN_EXT)
SMOKE_BIN ?= $(BUILD_DIR)/abi_smoke

# dlopen lives in libc since glibc 2.34; older Linux needs -ldl.
SMOKE_LDFLAGS =
ifeq ($(GOOS),linux)
SMOKE_LDFLAGS = -ldl
endif

.PHONY: build test vet fmt smoke check clean

build:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -buildmode=c-shared -ldflags "$(GO_LDFLAGS)" -o $(PLUGIN_OUTPUT) .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

smoke: build
	$(CC) test/abi_smoke.c -o $(SMOKE_BIN) $(SMOKE_LDFLAGS)
	$(SMOKE_BIN) $(PLUGIN_OUTPUT)

check: vet test smoke

clean:
	rm -rf $(BUILD_DIR)
