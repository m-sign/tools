# Go parameters
GOCMD = go
GOVARS = CGO_ENABLED=0
GOOUTDIR = bin
HOSTDIR = build/host

# Version information embedded in the binaries. DATE is the commit time, not
# the build time, so that builds of the same commit are reproducible.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo devel)
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE ?= $(shell git log -1 --format=%cI 2>/dev/null)

VERSIONPKG = $(GOMODULE)/internal/version
LDFLAGS = -s -w -X $(VERSIONPKG).Version=$(VERSION) -X $(VERSIONPKG).Commit=$(COMMIT) -X $(VERSIONPKG).Date=$(DATE)
GOBUILD = $(GOVARS) $(GOCMD) build -trimpath -ldflags "$(LDFLAGS)"

# Tools
GOLANGCI_LINT = golangci-lint
GOVULNCHECK = $(GOCMD) run golang.org/x/vuln/cmd/govulncheck@v1.9.0
SHA256SUM := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo "shasum -a 256")

# Platform specific settings
HOST_EXT :=
ifeq ($(OS),Windows_NT)
	HOST_EXT := .exe
endif

# exe returns .exe for windows targets
exe = $(if $(findstring windows,$(1)),.exe)
